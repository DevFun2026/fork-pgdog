import unittest

from agent_cli.redaction import redact


class RedactionTests(unittest.TestCase):
    def test_private_blocks_and_secrets_are_removed(self):
        value = "keep <no-memory>token=abc</no-memory> AKIAABCDEFGHIJKLMNOP"
        result = redact(value)
        self.assertEqual(
            result.text,
            "keep [REDACTED_PRIVATE] [REDACTED_SECRET]",
        )
        self.assertEqual(result.redaction_count, 2)

    def test_configured_literal_secret_is_not_returned(self):
        result = redact("prefix exact-secret suffix", secrets=("exact-secret",))
        self.assertEqual(result.text, "prefix [REDACTED_SECRET] suffix")
        self.assertNotIn("exact-secret", repr(result))

    def test_unclosed_private_block_redacts_to_end(self):
        result = redact("safe <no-memory>do-not-store")
        self.assertEqual(result.text, "safe [REDACTED_PRIVATE]")

    def test_private_key_body_is_removed(self):
        value = "before -----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY----- after"
        self.assertEqual(redact(value).text, "before [REDACTED_SECRET] after")


if __name__ == "__main__":
    unittest.main()
