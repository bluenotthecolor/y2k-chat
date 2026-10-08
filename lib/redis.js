// Tiny Redis client for serverless: talks to Upstash Redis over its REST API, so it
// needs no extra packages. Works with the Upstash integration from the Vercel
// Marketplace (it sets these environment variables for you).
"use strict";

const URL_ =
  process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL || "";
const TOKEN =
  process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN || "";

let injected = null; // tests can swap in a fake client with use()

exports.use = (client) => {
  injected = client;
};

exports.configured = () => !!injected || !!(URL_ && TOKEN);

async function rest(path, body) {
  const res = await fetch(URL_.replace(/\/$/, "") + path, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + TOKEN,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  let json;
  try {
    json = await res.json();
  } catch {
    throw new Error("redis: bad response (" + res.status + ")");
  }
  if (!res.ok) throw new Error("redis: " + (json && json.error ? json.error : res.status));
  return json;
}

const str = (a) => a.map((x) => String(x));

// run one command, e.g. cmd(["GET", "key"])
exports.cmd = async (args) => {
  if (injected) return injected.cmd(args);
  const j = await rest("", str(args));
  if (j.error) throw new Error("redis: " + j.error);
  return j.result;
};

// run several commands in one round trip, results come back in order
exports.pipeline = async (cmds) => {
  if (injected) return injected.pipeline(cmds);
  const j = await rest("/pipeline", cmds.map(str));
  return j.map((r) => {
    if (r.error) throw new Error("redis: " + r.error);
    return r.result;
  });
};
