'use strict';

/**
 * Mineflayer bot scenarios for VeloAuth end-to-end tests (offline mode only —
 * premium Mojang session auth cannot be simulated by a bot).
 *
 * Usage: node bot.js <host> <port> <username> <scenario>
 *
 * Scenarios:
 *   prompt-register  First contact with the auth server: assert the register/login
 *                    instructions arrive, assert the repeating reminder re-sends them,
 *                    then /register and assert success. This is the issue #48 scenario
 *                    when run as the first connection after proxy startup.
 *   login            Reconnect with an already-registered nickname: assert instructions
 *                    arrive, then /login and assert success.
 *
 * Exit code 0 on success; 1 with a message transcript on any failed assertion.
 */

const mineflayer = require('mineflayer');

const [host, portArg, username, scenario] = process.argv.slice(2);
const port = Number(portArg);
const PASSWORD = 'TestPass123';
const BOT_VERSION = '1.20.4';

const PROMPT_TIMEOUT_MS = 30_000;
const REMINDER_TIMEOUT_MS = 20_000; // reminder repeats every 10s; allow one missed beat
const RESULT_TIMEOUT_MS = 15_000;

if (!host || !port || !username || !['prompt-register', 'login'].includes(scenario)) {
  console.error('usage: node bot.js <host> <port> <username> <prompt-register|login>');
  process.exit(2);
}

const transcript = [];
let finished = false;

function fail(reason) {
  if (finished) return;
  finished = true;
  console.error(`E2E FAIL [${scenario}/${username}]: ${reason}`);
  console.error('--- transcript ---');
  for (const line of transcript) console.error(`  ${line}`);
  console.error('--- end transcript ---');
  process.exit(1);
}

function pass() {
  if (finished) return;
  finished = true;
  console.log(`E2E PASS [${scenario}/${username}]`);
  process.exit(0);
}

const bot = mineflayer.createBot({
  host,
  port,
  username,
  auth: 'offline',
  version: BOT_VERSION,
  // The proxy may still be initializing (EarlyLoginBlocker queue) - be patient.
  checkTimeoutInterval: 60_000,
});

bot.on('error', (err) => fail(`bot error: ${err.message}`));
bot.on('kicked', (reason) => {
  // A kick after the scenario goal was reached (e.g. dead dummy backend after
  // successful registration) is irrelevant; fail() / pass() already ran.
  fail(`kicked: ${JSON.stringify(reason)}`);
});
bot.on('end', (reason) => fail(`connection ended: ${reason}`));

/** Waits until the accumulated transcript satisfies `predicate`. */
function waitFor(description, timeoutMs, predicate) {
  return new Promise((resolve, reject) => {
    if (predicate()) return resolve();
    const timer = setTimeout(() => {
      bot.removeListener('messagestr', onMessage);
      reject(new Error(`timed out after ${timeoutMs}ms waiting for: ${description}`));
    }, timeoutMs);
    function onMessage() {
      if (predicate()) {
        clearTimeout(timer);
        bot.removeListener('messagestr', onMessage);
        resolve();
      }
    }
    bot.on('messagestr', onMessage);
  });
}

bot.on('messagestr', (message) => {
  transcript.push(message);
});

const countInstructions = () =>
  transcript.filter((m) => m.includes('/register') || m.includes('/login')).length;

async function run() {
  // The limbo serves a void world; mineflayer's 'spawn' can stay pending there,
  // so gate on protocol login instead - chat works from that point on.
  await new Promise((resolve) => {
    bot.once('login', resolve);
    bot.once('spawn', resolve);
  });
  transcript.push('<logged in>');

  if (scenario === 'prompt-register') {
    // 1. The auth instructions must reach the player (issue #48: they never did
    //    for the first player after proxy startup).
    await waitFor('auth instructions', PROMPT_TIMEOUT_MS, () => countInstructions() >= 1);

    // 2. The repeating reminder must re-send instructions even if the first
    //    one-shot prompt had been lost.
    await waitFor('repeating reminder', REMINDER_TIMEOUT_MS, () => countInstructions() >= 2);

    // 3. Registration must complete.
    bot.chat(`/register ${PASSWORD} ${PASSWORD}`);
    await waitFor('registration success', RESULT_TIMEOUT_MS, () =>
      transcript.some((m) => m.includes('registered successfully')));
  } else {
    await waitFor('auth instructions', PROMPT_TIMEOUT_MS, () => countInstructions() >= 1);
    bot.chat(`/login ${PASSWORD}`);
    await waitFor('login success', RESULT_TIMEOUT_MS, () =>
      transcript.some((m) => m.includes('Logged in successfully')));
  }
  pass();
}

run().catch((err) => fail(err.message));

setTimeout(() => fail('global scenario timeout'), 90_000);
