import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "./web-client/node_modules/typescript/lib/typescript.js";
import {
  WssValidationClient,
  encodeEnvelope,
  openBytesFrame,
  dataFrame,
} from "./wss-smoke.mjs";

// Execute the actual browser source after TypeScript erasure, with controlled
// WebSocket events and timers. No browser or live Gateway is needed.
const source = await readFile(
  new URL("./web-client/src/wss_session.ts", import.meta.url),
  "utf8",
);
const { outputText } = ts.transpileModule(source, {
  compilerOptions: {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
  },
});
const { WssImSession } = await import(
  `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`
);

function unmask(bytes) {
  let offset = 2;
  let size = bytes[1] & 127;
  if (size === 126) {
    size = bytes.readUInt16BE(2);
    offset = 4;
  }
  const mask = bytes.subarray(offset, offset + 4);
  return Buffer.from(
    bytes
      .subarray(offset + 4, offset + 4 + size)
      .map((byte, i) => byte ^ mask[i & 3]),
  );
}

function harness(t, kind) {
  const sent = [];
  let client;
  let timers;
  if (kind === "browser") {
    timers = new Map();
    let nextTimer = 0;
    const oldWindow = globalThis.window;
    const oldSocket = globalThis.WebSocket;
    globalThis.window = {
      setTimeout(callback) {
        const id = ++nextTimer;
        timers.set(id, callback);
        return id;
      },
      clearTimeout(id) {
        timers.delete(id);
      },
    };
    globalThis.WebSocket = { OPEN: 1 };
    const listeners = new Map();
    const socket = {
      readyState: 1,
      addEventListener(name, fn) {
        listeners.set(name, fn);
      },
      send(bytes) {
        sent.push(Buffer.from(bytes));
      },
      close() {},
    };
    client = new WssImSession(socket, "wss://test");
    t.after(() => {
      client.close();
      globalThis.window = oldWindow;
      globalThis.WebSocket = oldSocket;
    });
    return {
      client,
      sent,
      timers,
      begin: (none = false) => ({
        streamID: client.nextClientStreamID,
        result: client.exchange(
          openBytesFrame(1, 1, 2, none ? 1 : 0, "request"),
          none,
        ),
      }),
      receive(bytes) {
        const data = Uint8Array.from(bytes).buffer;
        listeners.get("message")({ data });
      },
      close() {
        socket.readyState = 3;
        listeners.get("error")?.({});
        listeners.get("close")({ code: 4002, reason: "kicked by peer" });
      },
    };
  }
  client = new WssValidationClient();
  client.socket = {
    write(bytes) {
      sent.push(unmask(bytes));
    },
    end() {},
  };
  t.after(() => client.failConnection(new Error("test cleanup")));
  return {
    client,
    sent,
    begin: (none = false, timeoutMS = 1000) => {
      const active = client.beginExchange({ noResponse: none, timeoutMS });
      active.send(
        openBytesFrame(1, 1, 2, none ? 1 : 0, "request", false),
        false,
      );
      return active;
    },
    receive: (bytes) => client.handleEnvelope(bytes),
    close() {
      client.failConnection(new Error("WSS closed (4002): kicked by peer"));
    },
  };
}

const control = (id, type, code) =>
  encodeEnvelope(id, Buffer.alloc(0), false, type, code);

for (const kind of ["browser", "smoke"]) {
  test(`${kind}: STOP keeps partial response, timer, and sibling; reciprocal RESET only stops upload`, async (t) => {
    const h = harness(t, kind);
    const active = h.begin();
    const sibling = h.begin();
    const pending = h.client.pending.get(active.streamID);
    const timer = pending.timer;
    const response = openBytesFrame(1, 1, 2, 0, "response after STOP");
    h.receive(encodeEnvelope(active.streamID, response.subarray(0, 5), false));
    h.receive(control(active.streamID, 3, 321));
    h.receive(control(active.streamID, 3, 321));
    assert.equal(h.client.pending.get(active.streamID), pending);
    assert.equal(pending.timer, timer);
    assert.equal(
      h.sent.length,
      3,
      "duplicate STOP must not send another RESET",
    );
    const reset = h.sent[2];
    assert.equal(reset[1], 2);
    assert.equal(reset[2], 0);
    assert.equal(reset.readBigUInt64BE(4), active.streamID);
    assert.equal(reset.readUInt32BE(12), 321);
    assert.equal(reset.readUInt32BE(16), 0);
    if (kind === "smoke") {
      assert.equal(
        active.send(dataFrame("must not upload", true), true),
        false,
      );
      assert.equal(h.sent.length, 3);
    }
    h.receive(
      encodeEnvelope(
        sibling.streamID,
        openBytesFrame(1, 1, 2, 0, "sibling"),
        true,
      ),
    );
    assert.equal(
      Buffer.from((await sibling.result).body).toString(),
      "sibling",
    );
    h.receive(encodeEnvelope(active.streamID, response.subarray(5), true));
    assert.equal(
      Buffer.from((await active.result).body).toString(),
      "response after STOP",
    );
    assert.equal(h.client.pending.size, 0);
    if (kind === "smoke")
      assert.equal(active.send(dataFrame("late"), false), false);
  });

  test(`${kind}: STOP followed by empty FIN completes no-response exchange`, async (t) => {
    const h = harness(t, kind);
    const active = h.begin(true);
    h.receive(control(active.streamID, 3, 55));
    h.receive(encodeEnvelope(active.streamID, Buffer.alloc(0), true));
    assert.equal(await active.result, null);
  });

  test(`${kind}: incoming RESET after STOP preserves actual response error`, async (t) => {
    const h = harness(t, kind);
    const active = h.begin();
    const rejection = assert.rejects(active.result, /987/);
    h.receive(control(active.streamID, 3, 123));
    h.receive(control(active.streamID, 2, 987));
    await rejection;
    assert.equal(h.client.pending.size, 0);
  });

  test(`${kind}: connection close after STOP preserves connection reason`, async (t) => {
    const h = harness(t, kind);
    const active = h.begin();
    const rejection = assert.rejects(active.result, /4002.*kicked by peer/);
    h.receive(control(active.streamID, 3, 123));
    h.close();
    await rejection;
    assert.equal(h.client.pending.size, 0);
  });

  test(`${kind}: STOP leaves original response deadline active`, async (t) => {
    const h = harness(t, kind);
    const active = h.begin(false, 20);
    const rejection = assert.rejects(active.result, /timeout|超时/);
    const timer = h.client.pending.get(active.streamID).timer;
    h.receive(control(active.streamID, 3, 123));
    if (kind === "browser") {
      assert.ok(h.timers.has(timer));
      h.timers.get(timer)();
    }
    await rejection;
    assert.equal(h.client.pending.size, 0);
  });

  test(`${kind}: STOP on a push preserves inbound bytes and suppresses reverse FIN`, async (t) => {
    const h = harness(t, kind);
    const body = Buffer.concat([
      Buffer.from([0, 0]),
      Buffer.from('{"ok":true,"type":"push"}'),
    ]);
    const frame = openBytesFrame(2, 1, 2, 1, body);
    const events = [];
    if (kind === "browser") h.client.onPush = (event) => events.push(event);
    h.receive(encodeEnvelope(1n, frame.subarray(0, 7), false));
    h.receive(control(1n, 3, 44));
    h.receive(encodeEnvelope(1n, frame.subarray(7), true));
    assert.equal((kind === "browser" ? events : h.client.events).length, 1);
    assert.equal(h.sent.length, 1);
    assert.equal(h.sent[0][1], 2);
    assert.equal(h.client.pushes.size, 0);
    assert.equal(h.client.stoppedPushUploads.size, 0);
  });

  test(`${kind}: RESET discards partial push state`, (t) => {
    const h = harness(t, kind);
    h.receive(encodeEnvelope(1n, Buffer.from([0, 1]), false));
    h.receive(control(1n, 3, 44));
    h.receive(control(1n, 2, 45));
    assert.equal(h.client.pushes.size, 0);
    assert.equal(h.client.stoppedPushUploads.size, 0);
  });
}

test("smoke: local STOP still allows request upload and peer RESET rejects response", async (t) => {
  const h = harness(t, "smoke");
  const active = h.begin();
  const rejection = assert.rejects(active.result, /RESET \(258\)/);
  active.stop(0x102);
  assert.equal(active.send(dataFrame("tail", true), true), true);
  h.receive(control(active.streamID, 2, 0x102));
  await rejection;
});

test("smoke: local RESET stops upload while retaining a committed response", async (t) => {
  const h = harness(t, "smoke");
  const active = h.begin();
  active.reset(77);
  assert.equal(active.send(dataFrame("tail"), false), false);
  h.receive(
    encodeEnvelope(
      active.streamID,
      openBytesFrame(1, 1, 2, 0, "committed"),
      true,
    ),
  );
  assert.equal((await active.result).body.toString(), "committed");
});

test("smoke: socket error is preserved through subsequent close", async (t) => {
  const h = harness(t, "smoke");
  const active = h.begin();
  const failure = new Error("ECONNRESET from TLS");
  const rejection = assert.rejects(active.result, (error) => error === failure);
  h.receive(control(active.streamID, 3, 5));
  h.client.failConnection(failure);
  h.close();
  await rejection;
});

for (const terminal of ["FIN", "RESET"]) {
  test(`smoke: response ${terminal} before STOP still stops an unfinished upload`, async (t) => {
    const h = harness(t, "smoke");
    const active = h.begin();
    const outcome =
      terminal === "RESET"
        ? assert.rejects(active.result, /RESET \(987\)/)
        : active.result;
    h.receive(
      terminal === "RESET"
        ? control(active.streamID, 2, 987)
        : encodeEnvelope(
            active.streamID,
            openBytesFrame(1, 1, 2, 0, "early response"),
            true,
          ),
    );
    await outcome;
    assert.equal(h.client.pending.size, 0);
    h.receive(control(active.streamID, 3, 123));
    assert.equal(active.send(dataFrame("must not upload", true), true), false);
    assert.equal(h.sent.at(-1)[1], 2);
    assert.equal(h.sent.at(-1).readUInt32BE(12), 123);
    assert.equal(h.client.uploads.size, 0);
  });
}

test("smoke: WebSocket close frame retains its code and reason after STOP", async (t) => {
  const h = harness(t, "smoke");
  const active = h.begin();
  const rejection = assert.rejects(active.result, /4003.*redirect/);
  h.receive(control(active.streamID, 3, 9));
  const payload = Buffer.alloc(2 + Buffer.byteLength("redirect"));
  payload.writeUInt16BE(4003);
  payload.write("redirect", 2);
  h.client.upgraded = true;
  h.client.input = Buffer.concat([
    Buffer.from([0x88, payload.length]),
    payload,
  ]);
  h.client.drainWebSocket();
  await rejection;
  assert.equal(h.client.websocketCloseCode, 4003);
  assert.equal(h.client.uploads.size, 0);
});
