import values from "../config/web-client.json";

export type WebClientConfig = {
  wssURL: string;
  clientAgentBaseURL: string;
};

export const config: WebClientConfig = {
  wssURL: values.wss_url,
  clientAgentBaseURL: values.client_agent_base_url.replace(/\/$/, ""),
};
