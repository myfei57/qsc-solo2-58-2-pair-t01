import unittest

from maskhub.discovery.names import normalize, phrase_hit, phrase_tokens


class NameMatchingTests(unittest.TestCase):
    def test_snake_and_camel_tokenize_to_ascii_tokens(self):
        self.assertEqual(normalize("user_email_addr"), "user email addr")
        self.assertEqual(normalize("emailAddress2"), "email address 2")

    def test_multi_token_phrases_match_on_token_boundaries(self):
        normalized = normalize("card_no")
        self.assertTrue(phrase_hit(normalized, "card_no"))
        self.assertTrue(phrase_hit(normalized, "card"))

    def test_keyword_does_not_match_inside_another_token(self):
        # "name" must not match a column literally called "filename"
        self.assertFalse(phrase_hit(normalize("filename"), "name"))
        self.assertFalse(phrase_hit(normalize("username_id"), "id_no"))

    def test_cjk_phrase_matches_inside_run(self):
        self.assertTrue(phrase_hit(normalize("客户手机号"), "手机"))
        self.assertTrue(phrase_hit(normalize("身份证号"), "身份证"))

    def test_phrase_tokens(self):
        self.assertEqual(phrase_tokens("card_no"), ["card", "no"])
        self.assertEqual(phrase_tokens("身份证"), ["身份证"])


if __name__ == "__main__":
    unittest.main()
