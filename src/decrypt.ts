import crypto from "crypto";
import { Data } from "./Protobufs.ts";
import logger from "./Logger.ts";

const decryptionKeys = [
  "1PG7OiApB1nwvP+rz05pAQ==", // add default "AQ==" decryption key

  "1PG7OiApB1nwvP+rz05pCQ==", // Ham | CQ== (0x09)
  "1PG7OiApB1nwvP+rz05pEQ==", // MeshQuake | EQ== (0x11)
  "1PG7OiApB1nwvP+rz05p5g==", // BayMeshNews | 5g== (0xE6)
  "1PG7OiApB1nwvP+rz05pSA==", // SF | SA== (0x48)
  "1PG7OiApB1nwvP+rz05pTQ==", // Test | TQ== (0x4D)
  "1PG7OiApB1nwvP+rz05pNA==", // CRUZ | NA== (0x34)
  "1PG7OiApB1nwvP+rz05pew==", // Boozin' | ew== (0x7B)
  "1PG7OiApB1nwvP+rz05p1A==", // First | 1A== (0xD4)
  "1PG7OiApB1nwvP+rz05peQ==", // Retro | eQ== (0x79)
].map((key) => Buffer.from(key, "base64"));

const cipherForKey = (key: Buffer) => {
  if (key.length === 16) {
    return "aes-128-ctr";
  }
  if (key.length === 32) {
    return "aes-256-ctr";
  }
  return null;
};

/**
 * Parse CHANNEL_KEYS: a JSON object of channel name -> base64 key, for
 * channels that have their own key (16 bytes = AES-128, 32 bytes = AES-256).
 * The key may be standard or URL-safe base64, as found in a Meshtastic
 * channel link. A bad entry is logged and skipped, never fatal.
 */
const parseChannelKeys = (raw: string | undefined) => {
  const keys = new Map<string, Buffer>();
  if (!raw || raw.trim().length === 0) {
    return keys;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    logger.error(`CHANNEL_KEYS is not valid JSON, ignoring it: ${String(err)}`);
    return keys;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    logger.error("CHANNEL_KEYS must be a JSON object of name -> base64 key");
    return keys;
  }
  for (const [name, value] of Object.entries(parsed)) {
    const key =
      typeof value === "string"
        ? Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64")
        : Buffer.alloc(0);
    if (!cipherForKey(key)) {
      logger.error(
        `CHANNEL_KEYS: key for channel '${name}' must be 16 or 32 bytes of base64, ignoring it`,
      );
      continue;
    }
    keys.set(name, key);
  }
  return keys;
};

// Read on first use, not at import, so the logger is initialised by then.
let channelKeys: Map<string, Buffer> | null = null;
const getChannelKeys = () => {
  if (!channelKeys) {
    channelKeys = parseChannelKeys(process.env.CHANNEL_KEYS);
    if (channelKeys.size > 0) {
      logger.info(
        `Loaded keys for channels: ${Array.from(channelKeys.keys()).join(", ")}`,
      );
    }
  }
  return channelKeys;
};

function createNonce(packetId, fromNode) {
  // Expand packetId to 64 bits
  const packetId64 = BigInt(packetId);

  // Initialize block counter (32-bit, starts at zero)
  const blockCounter = 0;

  // Create a buffer for the nonce
  const buf = Buffer.alloc(16);

  // Write packetId, fromNode, and block counter to the buffer
  buf.writeBigUInt64LE(packetId64, 0);
  buf.writeUInt32LE(fromNode, 8);
  buf.writeUInt32LE(blockCounter, 12);

  return buf;
}

/**
 * References:
 * https://github.com/crypto-smoke/meshtastic-go/blob/develop/radio/aes.go#L42
 * https://github.com/pdxlocations/Meshtastic-MQTT-Connect/blob/main/meshtastic-mqtt-connect.py#L381
 */
function decrypt(packet, channelId?: string) {
  // AES-CTR has no integrity check, so a wrong key can still produce bytes
  // that parse. A channel with its own key is therefore tried with that key
  // only, picked by the channel name on the MQTT envelope; every other
  // channel gets the shared default keys.
  const channelKey = channelId ? getChannelKeys().get(channelId) : undefined;
  const keys = channelKey ? [channelKey] : decryptionKeys;

  for (const key of keys) {
    try {
      // create decryption iv/nonce for this packet
      const nonceBuffer = createNonce(packet.id, packet.from);

      const decipher = crypto.createDecipheriv(
        cipherForKey(key),
        key,
        nonceBuffer,
      );

      // decrypt encrypted packet
      const decryptedBuffer = Buffer.concat([
        decipher.update(packet.encrypted),
        decipher.final(),
      ]);

      // parse as data message
      return Data.decode(decryptedBuffer);
    } catch (e) {
      // logger.info(e);
    }
  }

  // couldn't decrypt
  return null;
}

export { decrypt, parseChannelKeys };
