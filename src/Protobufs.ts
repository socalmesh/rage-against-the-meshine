import fs from "fs";
import { createRequire } from "module";
import { fileURLToPath } from "url";
import path, { dirname } from "path";
import protobufjs from "protobufjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Meshtastic's protos import google/protobuf/descriptor.proto, which is not in
// the protobufs repo. protobufjs ships a copy, so fall back to that one.
const require = createRequire(import.meta.url);
const protobufjsDir = dirname(require.resolve("protobufjs/package.json"));

const root = new protobufjs.Root();
root.resolvePath = (origin: string, target: string) => {
  const local = path.join(__dirname, "protobufs", target);
  if (target.startsWith("google/protobuf/") && !fs.existsSync(local)) {
    return path.join(protobufjsDir, target);
  }
  return local;
};
root.loadSync("meshtastic/mqtt.proto");

const Data = root.lookupType("Data");
const ServiceEnvelope = root.lookupType("ServiceEnvelope");
const Position = root.lookupType("Position");
const User = root.lookupType("User");

export { Data, ServiceEnvelope, Position, User };
