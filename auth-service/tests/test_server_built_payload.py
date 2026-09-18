"""Server-built wallet payloads for on-chain intents (onchain.custom_tx).

When the payer's client sends its Miden account (`sender_address`), the
ledger asks the note-builder for the wallet payload — the serialized
TransactionRequest the wallet signs — and returns it with the intent.
The client then needs no Miden SDK of its own. What is pinned here:

  * the payload is built ONCE and STORED: every /checkout retry hands
    back the same note. A rebuild would be a second payable note for the
    same memo, and two notes paid = one refund by hand;
  * a rebuild happens only when the payer names a DIFFERENT account —
    a Miden note names its sender and the wallet signs only for its own
    account, so the old payload is unusable from the new one anyway;
  * a builder that cannot serve, or a malformed sender, is refused
    BEFORE the intent row exists — the payer's capped pending slots are
    the thing being protected (same discipline as test_intent_preflight);
  * without a sender_address nothing changes: no builder call, no
    custom_tx — the legacy client-built path is intact;
  * the Stripe rail never touches the builder.

The builder is faked at onchain_client._builder_request (one seam), so
these tests never need the Node service or the WASM SDK.

Run from `auth-service/`:
    python -m unittest tests.test_server_built_payload -v
"""

import hashlib
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("ADMIN_TOKEN", "A" * 40)
os.environ.setdefault("PROXY_REFUND_TOKEN", "P" * 40)
os.environ.setdefault("AUTH_DB_PATH", ":memory:")

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app import handlers, onchain_client, stripe_client  # noqa: E402
from app.db import init_db as real_init_db  # noqa: E402


class _StripeStub:
    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, data=None, headers=None):
        class _Resp:
            status_code = 200

            @staticmethod
            def json():
                return {"id": "cs_stub", "url": "https://checkout.stripe.com/stub"}

        return _Resp()


class _FakeBuilder:
    """Scriptable stand-in for the note-builder HTTP service.

    Records every call; answers /health with `health_status` and /build
    with a payload whose transactionRequest embeds a counter, so two
    builds are distinguishable (like two random serials would be).
    """

    def __init__(self):
        self.calls = []
        self.health_status = 200
        self.build_status = 200
        self.raise_exc = None
        self.builds = 0

    async def __call__(self, method, path, json=None):
        self.calls.append((method, path, json))
        if self.raise_exc is not None:
            raise self.raise_exc
        if path == "/health":
            return httpx.Response(self.health_status, json={"ok": self.health_status == 200})
        assert path == "/build" and method == "POST"
        if self.build_status != 200:
            return httpx.Response(self.build_status, json={"error": "builder says no"})
        self.builds += 1
        return httpx.Response(200, json={
            "address": json["sender_address"],
            "recipientAddress": json["pay_to_address"],
            "transactionRequest": f"UEFZTE9BRC0{self.builds}",
            "note_id": "0x" + f"{self.builds:064x}",
        })


ADMIN = "a" * 32
WATCHER = "w" * 32
GATEWAY = "mtst1gatewayreceivingaccount000000000"
FAUCET = "mtst1azftenneus72ugqqsj9rk7cveqk0eraz"
SENDER_A = "mtst1ard3m9w34puygyqe5thme4u5dqhsr3np"
SENDER_B = "mtst1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
KEY_HASH = hashlib.sha256(b"lev_payload_owner").hexdigest()


class ServerBuiltPayloadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        db_path = os.path.join(cls._tmp.name, "auth.db")
        cls.db_path = db_path

        async def fake_init():
            return await real_init_db(db_path)

        cls.builder = _FakeBuilder()
        cls._patches = [
            patch.object(main, "init_db", fake_init),
            patch.object(main, "ADMIN_TOKEN", ADMIN),
            patch.object(main, "ONCHAIN_WATCHER_TOKEN", WATCHER),
            patch.object(main, "TOPUP_PROVIDER_OVERRIDE", ""),
            patch.object(main.limiter, "enabled", False),
            # One identity serves every test here and each leaves a pending
            # on-chain order behind; the per-rail cap (8) is not what these
            # tests exercise and would otherwise 400 whichever test runs 9th.
            patch.object(handlers, "ONCHAIN_MAX_PENDING_PER_IDENTITY", 1000),
            patch.object(onchain_client, "ONCHAIN_GATEWAY_ADDRESS", GATEWAY),
            patch.object(onchain_client, "ONCHAIN_FAUCET_ID", FAUCET),
            patch.object(onchain_client, "ONCHAIN_BUILDER_URL", "http://note-builder.test:8090"),
            patch.object(onchain_client, "_builder_request", cls.builder),
            patch.object(stripe_client, "STRIPE_SECRET_KEY", "sk_test_stub"),
            patch.object(stripe_client, "STRIPE_SUCCESS_URL", "https://app.example/ok"),
            patch.object(httpx, "AsyncClient", _StripeStub),
        ]
        for p in cls._patches:
            p.start()
        cls.client = TestClient(main.app)
        cls.client.__enter__()
        r = cls.client.post(
            "/v1/identities",
            headers={"authorization": f"Bearer {ADMIN}"},
            json={"credential_type": "api_key", "credential_value": KEY_HASH},
        )
        assert r.status_code == 201, r.text

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        for p in cls._patches:
            p.stop()
        cls._tmp.cleanup()

    def setUp(self):
        self.builder.calls.clear()
        self.builder.health_status = 200
        self.builder.build_status = 200
        self.builder.raise_exc = None

    # ── helpers ────────────────────────────────────────────────────────

    def _create(self, provider="onchain", sender=SENDER_A, credits=300):
        body = {"credential_type": "api_key", "credential_value": KEY_HASH,
                "credits": credits, "provider": provider}
        if sender is not None:
            body["sender_address"] = sender
        return self.client.post("/v1/payment-intents", json=body)

    def _checkout(self, memo, sender=None, credential=None):
        """`credential` = the api_key hash proving ownership (what the Edge
        adds for a wallet session); None = the public, unauthenticated call."""
        body = {} if sender is None else {"sender_address": sender}
        if credential is not None:
            body.update({"credential_type": "api_key", "credential_value": credential})
        return self.client.post(f"/v1/payment-intents/{memo}/checkout", json=body)

    def _matching_table(self):
        r = self.client.get("/v1/onchain/pending-intents",
                            headers={"authorization": f"Bearer {WATCHER}"})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["intents"]

    def _memos(self):
        return {i["memo"] for i in self._matching_table()}

    def _build_calls(self):
        return [c for c in self.builder.calls if c[1] == "/build"]

    # ── the happy path ─────────────────────────────────────────────────

    def test_create_with_sender_returns_a_stored_server_built_payload(self):
        r = self._create()
        self.assertEqual(r.status_code, 201, r.text)
        j = r.json()
        self.assertNotIn("checkout_error", j)
        tx = j["onchain"]["custom_tx"]
        self.assertEqual(tx["address"], SENDER_A)
        self.assertEqual(tx["recipientAddress"], GATEWAY)
        self.assertTrue(tx["transactionRequest"])
        self.assertRegex(tx["note_id"], r"^0x[0-9a-f]{64}$")

        # Exactly one build, with the ledger's OWN rail config and price.
        builds = self._build_calls()
        self.assertEqual(len(builds), 1)
        sent = builds[0][2]
        self.assertEqual(sent["sender_address"], SENDER_A)
        self.assertEqual(sent["pay_to_address"], GATEWAY)
        self.assertEqual(sent["faucet_id"], FAUCET)
        self.assertEqual(sent["memo"], j["memo"])
        self.assertEqual(sent["token_amount"],
                         str(onchain_client.token_amount_for_cents(j["amount_cents"])))
        # The health probe ran BEFORE the build (preflight ordering).
        self.assertEqual([c[1] for c in self.builder.calls], ["/health", "/build"])

        # The matching table carries the note the payer will publish.
        row = next(i for i in self._matching_table() if i["memo"] == j["memo"])
        self.assertEqual(row["expected_note_id"], tx["note_id"])

    def test_checkout_returns_the_same_stored_payload_without_rebuilding(self):
        memo = self._create().json()["memo"]
        first = self._build_calls()
        self.assertEqual(len(first), 1)
        created_tx = None
        for _ in range(3):
            r = self._checkout(memo)
            self.assertEqual(r.status_code, 200, r.text)
            tx = r.json()["onchain"]["custom_tx"]
            created_tx = created_tx or tx
            self.assertEqual(tx, created_tx)
        # Also when the SAME sender is named explicitly.
        r = self._checkout(memo, sender=SENDER_A)
        self.assertEqual(r.json()["onchain"]["custom_tx"], created_tx)
        self.assertEqual(len(self._build_calls()), 1, "a retry must not mint a second note")

    def test_checkout_for_a_different_sender_rebuilds_once_and_sticks(self):
        j = self._create().json()
        memo, tx_a = j["memo"], j["onchain"]["custom_tx"]

        r = self._checkout(memo, sender=SENDER_B, credential=KEY_HASH)   # the owner asks
        self.assertEqual(r.status_code, 200, r.text)
        tx_b = r.json()["onchain"]["custom_tx"]
        self.assertEqual(tx_b["address"], SENDER_B)
        self.assertNotEqual(tx_b["transactionRequest"], tx_a["transactionRequest"])
        self.assertNotEqual(tx_b["note_id"], tx_a["note_id"])
        self.assertEqual(len(self._build_calls()), 2)

        # From now on the stored payload is B's — retries stay on it, and
        # the matching table follows.
        self.assertEqual(self._checkout(memo).json()["onchain"]["custom_tx"], tx_b)
        self.assertEqual(self._checkout(memo, sender=SENDER_B).json()["onchain"]["custom_tx"], tx_b)
        self.assertEqual(len(self._build_calls()), 2)
        row = next(i for i in self._matching_table() if i["memo"] == memo)
        self.assertEqual(row["expected_note_id"], tx_b["note_id"])

    # ── refusals that must not cost a slot ─────────────────────────────

    def test_builder_unreachable_is_503_and_no_row(self):
        before = self._memos()
        self.builder.raise_exc = httpx.ConnectError("connection refused")
        r = self._create()
        self.assertEqual(r.status_code, 503, r.text)
        self.assertIn("note-builder", r.json()["detail"])
        self.assertEqual(self._memos(), before)
        self.assertEqual(self._build_calls(), [])

    def test_builder_not_ready_is_503_and_no_row(self):
        before = self._memos()
        self.builder.health_status = 503
        r = self._create()
        self.assertEqual(r.status_code, 503, r.text)
        self.assertEqual(self._memos(), before)
        self.assertEqual(self._build_calls(), [])

    def test_wallet_style_suffixed_address_is_accepted_verbatim(self):
        # The Leviathan wallet hands dApps `mtst1…_<interface>` (Address form),
        # not the bare account id. Rejecting it broke the very first
        # production attempt; the builder echoes it back unchanged and the
        # SDK compares that echo with the connected account, so it must
        # travel verbatim.
        suffixed = SENDER_A + "_qr7qqq9wr6w"
        r = self._create(sender=suffixed)
        self.assertEqual(r.status_code, 201, r.text)
        tx = r.json()["onchain"]["custom_tx"]
        self.assertEqual(tx["address"], suffixed)
        self.assertEqual(self._build_calls()[-1][2]["sender_address"], suffixed)

    def test_malformed_sender_is_400_and_no_row(self):
        before = self._memos()
        for bad in ["", "not-an-address", "MTST1UPPERCASE00000000000000000000000",
                    "mm1" + "q" * 36]:   # last: mainnet payer, testnet gateway
            r = self._create(sender=bad)
            self.assertIn(r.status_code, (400, 422), f"{bad!r}: {r.text}")
        self.assertEqual(self._memos(), before)
        self.assertEqual(self.builder.calls, [])

    def test_builder_disabled_is_503_and_no_row(self):
        before = self._memos()
        with patch.object(onchain_client, "ONCHAIN_BUILDER_URL", ""):
            r = self._create()
        self.assertEqual(r.status_code, 503, r.text)
        self.assertIn("ONCHAIN_BUILDER_URL", r.json()["detail"])
        self.assertEqual(self._memos(), before)

    # ── a transient build failure AFTER preflight is recoverable ───────

    def test_transient_build_failure_is_soft_and_checkout_recovers(self):
        self.builder.build_status = 500
        r = self._create()
        self.assertEqual(r.status_code, 201, r.text)   # preflight passed; row exists
        j = r.json()
        self.assertIn("checkout_error", j)
        self.assertIn("note-builder", j["checkout_error"])
        self.assertNotIn("onchain", j)
        memo = j["memo"]
        self.assertIn(memo, self._memos())

        # Builder recovers; the client retries with its sender (through
        # its session, so the owner credential rides along) and gets a
        # payload, which is then stored like any other.
        self.builder.build_status = 200
        r = self._checkout(memo, sender=SENDER_A, credential=KEY_HASH)
        self.assertEqual(r.status_code, 200, r.text)
        tx = r.json()["onchain"]["custom_tx"]
        self.assertEqual(tx["address"], SENDER_A)
        self.assertEqual(self._checkout(memo).json()["onchain"]["custom_tx"], tx)

    # ── the paths that must not change ─────────────────────────────────

    def test_without_sender_the_legacy_client_built_path_is_untouched(self):
        r = self._create(sender=None)
        self.assertEqual(r.status_code, 201, r.text)
        j = r.json()
        self.assertNotIn("custom_tx", j["onchain"])
        self.assertEqual(self.builder.calls, [])
        # ...and /checkout without a sender hands back plain instructions.
        r = self._checkout(j["memo"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertNotIn("custom_tx", r.json()["onchain"])
        self.assertEqual(self.builder.calls, [])
        # A later checkout WITH a sender — from the owner — upgrades the
        # intent to a stored payload.
        r = self._checkout(j["memo"], sender=SENDER_A, credential=KEY_HASH)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["onchain"]["custom_tx"]["address"], SENDER_A)
        self.assertEqual(len(self._build_calls()), 1)

    # ── the public route is READ-ONLY for the payload ──────────────────
    # Reviewer finding (2026-09-18): /checkout is deliberately public, and
    # the memo is public on-chain once a note commits. Rebuilding on a
    # foreign sender therefore let anyone drive the builder and overwrite
    # expected_note_id. Reads stay open; writes need the owner.

    def test_public_checkout_cannot_replace_the_stored_payload(self):
        j = self._create().json()
        memo, tx_a = j["memo"], j["onchain"]["custom_tx"]
        builds_before = len(self._build_calls())

        r = self._checkout(memo, sender=SENDER_B)              # no credential
        self.assertEqual(r.status_code, 403, r.text)
        self.assertIn("owner", r.json()["detail"])
        self.assertEqual(len(self._build_calls()), builds_before, "builder must not be driven")
        # Stored payload and the reconciliation note id are untouched.
        self.assertEqual(self._checkout(memo).json()["onchain"]["custom_tx"], tx_a)
        row = next(i for i in self._matching_table() if i["memo"] == memo)
        self.assertEqual(row["expected_note_id"], tx_a["note_id"])

    def test_public_checkout_still_reads_the_stored_payload_for_its_own_sender(self):
        j = self._create().json()
        memo, tx_a = j["memo"], j["onchain"]["custom_tx"]
        builds_before = len(self._build_calls())
        # Same sender as stored: a read, allowed without credential.
        r = self._checkout(memo, sender=SENDER_A)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["onchain"]["custom_tx"], tx_a)
        # No sender at all: also a read.
        self.assertEqual(self._checkout(memo).status_code, 200)
        self.assertEqual(len(self._build_calls()), builds_before)

    def test_public_checkout_cannot_seed_a_payload_on_a_bare_intent(self):
        memo = self._create(sender=None).json()["memo"]        # legacy: nothing stored
        r = self._checkout(memo, sender=SENDER_B)
        self.assertEqual(r.status_code, 403, r.text)
        self.assertEqual(self._build_calls(), [])
        row = next(i for i in self._matching_table() if i["memo"] == memo)
        self.assertIsNone(row["expected_note_id"])

    def test_someone_elses_credential_is_refused_like_an_unknown_one(self):
        memo = self._create().json()["memo"]
        other = hashlib.sha256(b"lev_someone_else").hexdigest()
        r = self.client.post("/v1/identities", headers={"authorization": f"Bearer {ADMIN}"},
                             json={"credential_type": "api_key", "credential_value": other})
        self.assertEqual(r.status_code, 201, r.text)
        builds_before = len(self._build_calls())
        for cred in (other, hashlib.sha256(b"never_issued").hexdigest()):
            r = self._checkout(memo, sender=SENDER_B, credential=cred)
            self.assertEqual(r.status_code, 403, r.text)
            self.assertEqual(r.json()["detail"], "credential does not own this intent")
        self.assertEqual(len(self._build_calls()), builds_before)

    def test_malformed_credential_is_401_before_any_provider_call(self):
        memo = self._create().json()["memo"]
        builds_before = len(self._build_calls())
        r = self.client.post(f"/v1/payment-intents/{memo}/checkout",
                             json={"credential_type": "miden_wallet", "credential_value": "x",
                                   "sender_address": SENDER_B})
        self.assertEqual(r.status_code, 401, r.text)
        self.assertEqual(len(self._build_calls()), builds_before)

    # ── the quote is frozen: a rate change prices NEW intents only ─────
    # Reviewer finding (2026-09-18): the payload fixed the token amount at
    # build time, but the matching table and the webhook recomputed the
    # expectation from the live rate. Changing ONCHAIN_CENTS_PER_TOKEN (or
    # decimals) inside the 24h TTL + 48h grace turned every real in-flight
    # note into a mismatch → 409 → dead-letter.

    def _webhook(self, memo, units):
        return self.client.post(
            "/v1/webhooks/onchain",
            headers={"authorization": f"Bearer {WATCHER}"},
            json={"memo": memo, "note_id": "0x" + hashlib.sha256(f"{memo}{units}".encode()).hexdigest(),
                  "faucet_id": FAUCET, "amount_base_units": str(units), "note_kind": "p2id"},
        )

    def test_rate_change_after_creation_does_not_break_an_in_flight_payment(self):
        j = self._create().json()
        memo = j["memo"]
        quoted = int(j["onchain"]["token_amount"])
        self.assertEqual(j["token_amount"], str(quoted))                 # frozen on the row
        self.assertEqual(self._build_calls()[-1][2]["token_amount"], str(quoted))

        # Operator doubles the token price while the order is open.
        with patch.object(onchain_client, "ONCHAIN_CENTS_PER_TOKEN",
                          onchain_client.ONCHAIN_CENTS_PER_TOKEN * 2):
            repriced = onchain_client.token_amount_for_cents(j["amount_cents"])
            self.assertNotEqual(repriced, quoted, "test premise: the live rate now differs")

            # 1. The watcher's table still names the QUOTED figure.
            row = next(i for i in self._matching_table() if i["memo"] == memo)
            self.assertEqual(row["token_amount"], str(quoted))

            # 2. A /checkout rebuild for another account pays the SAME quote.
            r = self._checkout(memo, sender=SENDER_B, credential=KEY_HASH)
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["onchain"]["token_amount"], str(quoted))
            self.assertEqual(self._build_calls()[-1][2]["token_amount"], str(quoted))

            # 3. A note paying today's re-priced figure is NOT the quote → refused…
            r = self._webhook(memo, repriced)
            self.assertEqual(r.status_code, 409, r.text)

            # 4. …and the note paying the quote is credited at the quoted PRICE.
            r = self._webhook(memo, quoted)
            self.assertEqual(r.status_code, 200, r.text)
            self.assertTrue(r.json()["result"]["success"])
        status = self.client.get(f"/v1/payment-intents/{memo}").json()
        self.assertEqual(status["status"], "paid")
        self.assertEqual(status["credits"], j["credits"])

    def test_legacy_row_without_a_frozen_quote_is_priced_from_the_live_rate(self):
        # Rows created before the column exist in production; for them the
        # pre-freeze behaviour is preserved exactly.
        import sqlite3
        j = self._create(sender=None).json()
        memo = j["memo"]
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE payment_intents SET token_amount = NULL WHERE memo = ?", (memo,))
        with patch.object(onchain_client, "ONCHAIN_CENTS_PER_TOKEN",
                          onchain_client.ONCHAIN_CENTS_PER_TOKEN * 2):
            live = str(onchain_client.token_amount_for_cents(j["amount_cents"]))
            row = next(i for i in self._matching_table() if i["memo"] == memo)
            self.assertEqual(row["token_amount"], live)
            r = self._webhook(memo, int(live))
            self.assertEqual(r.status_code, 200, r.text)

    def test_stripe_intents_carry_no_token_quote(self):
        j = self._create(provider="stripe", sender=None).json()
        self.assertIsNone(j.get("token_amount"))

    def test_bad_credential_on_a_stripe_intent_never_mints_a_checkout_session(self):
        # Ownership is checked BEFORE the provider call on every rail: a
        # refused request must not leave a live Stripe Checkout Session behind.
        memo = self._create(provider="stripe", sender=None).json()["memo"]
        r = self._checkout(memo, credential=hashlib.sha256(b"never_issued").hexdigest())
        self.assertEqual(r.status_code, 403, r.text)
        # and the owner still can
        r = self._checkout(memo, credential=KEY_HASH)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("checkout.stripe.com", r.json()["invoice_url"])

    def test_operator_override_onto_onchain_still_yields_a_payload(self):
        # Reviewer finding (2026-09-18): the SDK used to send sender_address
        # only when the CLIENT asked for on-chain. With
        # TOPUP_PROVIDER_OVERRIDE=onchain and a client asking for Stripe, the
        # server (rightly) made an on-chain order — but without a sender it
        # had no payload, and the first payTopup failed. The SDK now sends
        # the sender on every rail; this pins the server half: the override
        # rail gets its payload from a sender sent alongside a Stripe request.
        with patch.object(main, "TOPUP_PROVIDER_OVERRIDE", "onchain"):
            r = self._create(provider="stripe", sender=SENDER_A)
        self.assertEqual(r.status_code, 201, r.text)
        j = r.json()
        self.assertEqual(j["provider"], "onchain")            # the server's rail…
        self.assertEqual(j["onchain"]["custom_tx"]["address"], SENDER_A)   # …with its payload
        self.assertEqual(len(self._build_calls()), 1)

    def test_stripe_rail_ignores_sender_and_never_calls_the_builder(self):
        r = self._create(provider="stripe", sender=SENDER_A)
        self.assertEqual(r.status_code, 201, r.text)
        j = r.json()
        self.assertEqual(j["provider"], "stripe")
        self.assertIn("checkout.stripe.com", j["invoice_url"])
        self.assertNotIn("onchain", j)
        self.assertEqual(self.builder.calls, [])

    def test_public_status_endpoint_does_not_ship_the_payload(self):
        # /v1/payment-intents/{memo} is polled every few seconds by
        # waitForTopup; a 30 KB payload does not belong in it.
        memo = self._create().json()["memo"]
        r = self.client.get(f"/v1/payment-intents/{memo}")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertNotIn("custom_tx", r.text)
        self.assertNotIn("transactionRequest", r.text)

    def test_builder_answering_for_other_parties_is_refused(self):
        original = self.builder.__call__

        async def swapped(method, path, json=None):
            resp = await original(method, path, json)
            if path == "/build":
                data = resp.json()
                data["recipientAddress"] = "mtst1somebodyelse00000000000000000000"
                return httpx.Response(200, json=data)
            return resp

        with patch.object(onchain_client, "_builder_request", swapped):
            r = self._create()
        # Preflight passed, so the row exists; the bad payload is refused
        # as a soft error rather than handed to a wallet.
        self.assertEqual(r.status_code, 201, r.text)
        j = r.json()
        self.assertIn("checkout_error", j)
        self.assertIn("other parties", j["checkout_error"])
        self.assertNotIn("onchain", j)


if __name__ == "__main__":
    unittest.main()
