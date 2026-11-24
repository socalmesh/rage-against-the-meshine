import crypto from "crypto";

// Fixed keys, so the wrong-key cases below give the same result every run.
const KEY_256 = Buffer.from(Array.from({ length: 32 }, (_, i) => 0xa0 + i));
const OTHER_KEY_256 = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x40 + i));
const DEFAULT_KEY = Buffer.from("1PG7OiApB1nwvP+rz05pAQ==", "base64");

process.env.CHANNEL_KEYS = JSON.stringify({
  SoCalMesh: KEY_256.toString("base64"),
  // URL-safe base64 without padding.
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
    expect(textOf(decrypt(packet, "LongTurbo"))).toBeNull();
    expect(textOf(decrypt(packet, "SoCalAlerts"))).toBeNull();
    expect(textOf(decrypt(packet))).toBeNull();
  });

  it("still decrypts default-key channels", () => {
    const packet = encrypt(DEFAULT_KEY, "public");
    expect(textOf(decrypt(packet, "LongTurbo"))).toBe("public");
    expect(textOf(decrypt(packet))).toBe("public");
  });

  it("uses only the channel's own key for a keyed channel", () => {
    const packet = encrypt(DEFAULT_KEY, "public");
    expect(textOf(decrypt(packet, "SoCalMesh"))).toBeNull();
  });
});

describe("decrypt, independent vector", () => {
  // Ciphertext made with `openssl enc -aes-256-ctr`, key 00 01 .. 1f, for
  // packet id 0x1234abcd from 0xdeadbeef. Longer than one AES block.
  it("matches OpenSSL for a multi-block AES-256 packet", () => {
    jest.resetModules();
    process.env.CHANNEL_KEYS = JSON.stringify({
      Vector: Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString("base64"),
    });
    const fresh = require("../src/decrypt");
    const decoded = fresh.decrypt(
      {
        id: PACKET_ID,
        from: FROM,
        encrypted: Buffer.from(
          "50bcb1ac42cf21b1a5712c1345233df6c3088c4add1e8e12c2893b41c4b506d75fc33600e96cae92dba3048a68fd0cfd4b0e3fd3e9d7c5",
          "hex",
        ),
      },
      "Vector",
    );
    expect(textOf(decoded)).toBe(
      "independent vector: more than one AES block of text",
    );
  });
});

describe("parseChannelKeys", () => {
  const good = KEY_256.toString("base64");

  it("accepts 16 and 32 byte keys, padded or not", () => {
    const keys = parseChannelKeys(
      JSON.stringify({
        A: good,
        B: KEY_256.toString("base64url"),
        C: DEFAULT_KEY.toString("base64"),
      }),
    );
    expect(keys.get("A")).toEqual(KEY_256);
    expect(keys.get("B")).toEqual(KEY_256);
    expect(keys.get("C")).toEqual(DEFAULT_KEY);
  });

  it("returns nothing when unset", () => {
    expect(parseChannelKeys(undefined).size).toBe(0);
    expect(parseChannelKeys("  ").size).toBe(0);
  });

  it("throws on a bad entry instead of leaving that channel on the default keys", () => {
    for (const bad of ["AQ==", 5, `${good}trailing`, `${good} `, ""]) {
      expect(() =>
        parseChannelKeys(JSON.stringify({ Good: good, Bad: bad })),
      ).toThrow("key for channel 'Bad'");
    }
  });

  it("throws on malformed or non-object input without echoing it", () => {
    const unquoted = `{"SoCalMesh": ${good}}`;
    let message = "";
    try {
      parseChannelKeys(unquoted);
    } catch (err) {
      message = String(err);
    }
    expect(message).toContain("CHANNEL_KEYS is not valid JSON");
    expect(message).not.toContain(good.slice(0, 6));
    expect(() => parseChannelKeys("[]")).toThrow("must be a JSON object");
  });
});
