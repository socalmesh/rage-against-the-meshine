// Discord rejects a whole message when one embed field value is longer than
// 1024 characters, so the gateway list has to be split to fit.

jest.mock("../src/Protobufs", () => ({
  __esModule: true,
  Position: { decode: jest.fn() },
}));

import { createDiscordMessage } from "../src/DiscordMessageUtils";

const FIELD_VALUE_LIMIT = 1024;

const meshRedis: any = {
  getNodeInfos: jest.fn(async () => ({})),
  getDiscordUserId: jest.fn(async () => null),
};

const logger: any = {
  info: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
  error: jest.fn(),
};

// One text packet heard by `gatewayCount` gateways, each `hops` hops away.
const buildPacketGroup = (gatewayCount: number, hops: number) => ({
  id: 123456789,
  time: new Date(0),
  serviceEnvelopes: Array.from({ length: gatewayCount }, (_, i) => ({
    gatewayId: `!${(0x40000000 + i).toString(16)}`,
    mqttTime: new Date(0),
    packet: {
      from: 0x12345678,
      id: 123456789,
      rxTime: 0,
      hopStart: 3,
      hopLimit: 3 - hops,
      rxSnr: 5.25,
      rxRssi: -90,
      decoded: { portnum: 1, payload: Buffer.from("hi") },
    },
  })),
});

const gatewayFieldsFor = async (
  baseUrl: string,
  gatewayCount: number,
  hops: number,
) => {
  const content: any = await createDiscordMessage(
    buildPacketGroup(gatewayCount, hops),
    "hi",
    {},
    {},
    meshRedis,
    baseUrl,
    logger,
    "baymesh",
    new Map(),
  );
  return content.embeds[0].fields.filter((field: any) =>
    field.value.includes("/packet_list/"),
  );
};

// Every base URL length from 9 to 68 characters, so that some of them put a
// field exactly on the limit.
const BASE_URLS = Array.from(
  { length: 60 },
  (_, i) => `https://${"m".repeat(i + 1)}`,
);

describe("gateway fields", () => {
  it.each([
    ["relayed gateways, joined with ' | '", 2],
    ["direct gateways, joined with a newline", 0],
  ])("keeps every field within Discord's limit: %s", async (_name, hops) => {
    const gatewayCount = 40;
    for (const baseUrl of BASE_URLS) {
      const fields = await gatewayFieldsFor(baseUrl, gatewayCount, hops);
      const longest = Math.max(...fields.map((f: any) => f.value.length));
      expect({ baseUrl, longest: longest <= FIELD_VALUE_LIMIT }).toEqual({
        baseUrl,
        longest: true,
      });

      // Splitting must not drop a gateway.
      const listed = fields
        .map((f: any) => f.value.split("/packet_list/").length - 1)
        .reduce((a: number, b: number) => a + b, 0);
      expect(listed).toBe(gatewayCount);
    }
  });
});
