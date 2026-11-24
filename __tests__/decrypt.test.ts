import crypto from "crypto";

const KEY_256 = crypto.randomBytes(32);
const OTHER_KEY_256 = crypto.randomBytes(32);
const DEFAULT_KEY = Buffer.from("1PG7OiApB1nwvP+rz05pAQ==", "base64");

process.env.CHANNEL_KEYS = JSON.stringify({
  SoCalMesh: KEY_256.toString("base64"),
  // URL-safe base64 without padding, the form a channel link carries.
  SoCalAlerts: OTHER_KEY_256.toString("base64url"),
});

// src/Protobufs.ts loads the .proto files from disk and does not load under
// jest. The two Data fields this test needs are declared here instead.
jest.mock("../src/Protobufs", () => {
  const protobufjs = require("protobufjs");
  const Data = new protobufjs.Type("Data")
    .add(new protobufjs.Field("portnum", 1, "int32"))
    .add(new protobufjs.Field("payload", 2, "bytes"));
  new protobufjs.Root().add(Data);
  return { __esModule: true, Data };
});

import { decrypt, parseChannelKeys } from "../src/decrypt";
import { Data } from "../src/Protobufs";

const PACKET_ID = 0x1234abcd;
const FROM = 0xdeadbeef;

const encrypt = (key: Buffer, text: string) => {
  const nonce = Buffer.alloc(16);
  nonce.writeBigUInt64LE(BigInt(PACKET_ID), 0);
  nonce.writeUInt32LE(FROM, 8);
  const plain = Buffer.from(
    Data.encode(Data.create({ portnum: 1, payload: Buffer.from(text) })).finish(),
  );
  const cipher = crypto.createCipheriv(
    key.length === 32 ? "aes-256-ctr" : "aes-128-ctr",
    key,
    nonce,
  );
  return {
    id: PACKET_ID,
    from: FROM,
    encrypted: Buffer.concat([cipher.update(plain), cipher.final()]),
  };
};

const textOf = (decoded: any) =>
  decoded && decoded.portnum === 1
    ? Buffer.from(decoded.payload).toString()
    : null;

describe("decrypt", () => {
  it("decrypts a channel that has its own 32-byte key", () => {
    const packet = encrypt(KEY_256, "hello socal");
    expect(textOf(decrypt(packet, "SoCalMesh"))).toBe("hello socal");
  });

  it("accepts a URL-safe base64 key", () => {
    const packet = encrypt(OTHER_KEY_256, "alert");
    expect(textOf(decrypt(packet, "SoCalAlerts"))).toBe("alert");
  });

  it("does not read a keyed channel's packet under another channel name", () => {
    const packet = encrypt(KEY_256, "hello socal");
    expect(textOf(decrypt(packet, "LongTurbo"))).not.toBe("hello socal");
    expect(textOf(decrypt(packet, "SoCalAlerts"))).not.toBe("hello socal");
    expect(textOf(decrypt(packet))).not.toBe("hello socal");
  });

  it("still decrypts default-key channels", () => {
    const packet = encrypt(DEFAULT_KEY, "public");
    expect(textOf(decrypt(packet, "LongTurbo"))).toBe("public");
    expect(textOf(decrypt(packet))).toBe("public");
  });

  it("uses only the channel's own key for a keyed channel", () => {
    const packet = encrypt(DEFAULT_KEY, "public");
    expect(textOf(decrypt(packet, "SoCalMesh"))).not.toBe("public");
  });
});

describe("parseChannelKeys", () => {
  it("skips bad entries and keeps good ones", () => {
    const keys = parseChannelKeys(
      JSON.stringify({
        Good: KEY_256.toString("base64"),
        Short: "AQ==",
        NotAString: 5,
      }),
    );
    expect(Array.from(keys.keys())).toEqual(["Good"]);
  });

  it("returns nothing for missing, malformed or non-object input", () => {
    expect(parseChannelKeys(undefined).size).toBe(0);
    expect(parseChannelKeys("not-json").size).toBe(0);
    expect(parseChannelKeys("[]").size).toBe(0);
  });
});
