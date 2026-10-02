"""The classifier decides what a human reads, so it must not guess or be forged."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from credential_profile import (
    AWS,
    PASSKEYS,
    SSH,
    classify_public_metadata,
    describe,
    public_label,
)


class ClassificationTests(unittest.TestCase):
    def test_openssh_applications_are_ssh(self):
        for rp_id in ("ssh:", "ssh:mybox", "ssh:example.com", "ssh:a/b"):
            self.assertEqual(classify_public_metadata(rp_id), SSH, rp_id)

    def test_documented_aws_domains_are_aws(self):
        for rp_id in (
            "signin.aws.amazon.com",
            "aws.amazon.com",
            "awsapps.com",
            "d-1234567890.awsapps.com",
            "mycompany.awsapps.com",
            "app.aws",
            "ssoins-1234.portal.eu-central-1.app.aws",
            "console.amazonaws.com",
        ):
            self.assertEqual(classify_public_metadata(rp_id), AWS, rp_id)

    def test_a_lookalike_domain_is_not_aws(self):
        """The label boundary is the whole protection here.

        Anyone can buy a domain that ends in the same letters. Only a match on a
        label boundary means the name is actually under AWS.
        """
        for rp_id in (
            "not-awsapps.com",
            "evilawsapps.com",
            "awsapps.com.attacker.example",
            "fakeaws.amazon.com.evil.test",
            "app.aws.evil.test",
            "xapp.aws.evil.test",
        ):
            self.assertEqual(classify_public_metadata(rp_id), PASSKEYS, rp_id)

    def test_everything_else_is_a_passkey(self):
        for rp_id in ("example.com", "webauthn.io", "github.com", "localhost"):
            self.assertEqual(classify_public_metadata(rp_id), PASSKEYS, rp_id)

    def test_a_trailing_dot_and_case_do_not_change_the_answer(self):
        for rp_id in ("AWSAPPS.COM", "awsapps.com.", "Mycompany.AwsApps.Com."):
            self.assertEqual(classify_public_metadata(rp_id), AWS, rp_id)

    def test_nothing_usable_is_a_passkey_rather_than_an_error(self):
        for rp_id in ("", None, 7, b"awsapps.com", [], {}):
            self.assertEqual(classify_public_metadata(rp_id), PASSKEYS, repr(rp_id))

    def test_the_relying_party_name_cannot_change_the_family(self):
        """Classification reads the id and nothing else.

        A site chooses its own name. If the name could classify, any site could
        present itself as AWS in the list.
        """
        credential = {
            "rp_id": "evil.example",
            "rp_name": "AWS IAM Identity Center",
            "user_name": "ssh:root",
        }
        self.assertEqual(describe(credential),
                         "[passkeys] evil.example (ssh:root)")


class LabelTests(unittest.TestCase):
    def test_the_label_leads_with_the_bound_identity(self):
        self.assertEqual(
            public_label({"rp_id": "example.com", "user_name": "ann"}),
            "example.com (ann)",
        )

    def test_the_display_name_is_used_only_when_there_is_no_user_name(self):
        self.assertEqual(
            public_label({"rp_id": "example.com", "user_display_name": "Ann A"}),
            "example.com (Ann A)",
        )
        self.assertEqual(
            public_label({"rp_id": "example.com", "user_name": "ann",
                          "user_display_name": "Ann A"}),
            "example.com (ann)",
        )

    def test_the_relying_party_name_never_appears(self):
        """A site's own name beside its id is how a list gets spoofed."""
        label = public_label({
            "rp_id": "evil.example",
            "rp_name": "Google",
            "user_name": "ann",
        })
        self.assertNotIn("Google", label)
        self.assertEqual(label, "evil.example (ann)")

    def test_control_and_direction_characters_are_removed(self):
        label = public_label({
            "rp_id": "example.com",
            # A right-to-left override makes the rest of a line render backwards,
            # which is the oldest trick for making one name read as another.
            "user_name": "ann\u202egro.live\u202c\r\n\x00\u200b",
        })
        for forbidden in ("\u202e", "\u202c", "\r", "\n", "\x00", "\u200b"):
            self.assertNotIn(forbidden, label)
        self.assertEqual(label, "example.com (anngro.live)")

    def test_a_name_cannot_forge_the_shape_of_a_label(self):
        # Whatever the name contains, the id stays first and the name stays inside
        # the parentheses, so the first token is always the bound identity.
        label = public_label({
            "rp_id": "evil.example",
            "user_name": "aws.amazon.com (admin)",
        })
        self.assertTrue(label.startswith("evil.example ("))

    def test_long_names_are_bounded_but_the_identity_is_not(self):
        long_id = "a" * 200 + ".example.com"
        label = public_label({"rp_id": long_id, "user_name": "b" * 200})
        self.assertTrue(label.startswith(long_id + " ("))
        self.assertEqual(len(label), len(long_id) + len("b" * 32) + 3)

    def test_a_credential_with_no_identity_says_so(self):
        for credential in ({}, {"rp_id": ""}, {"rp_id": "\u200b\u202e"}):
            self.assertEqual(public_label(credential), "unidentified credential")

    def test_attributes_work_as_well_as_mapping_keys(self):
        class Credential:
            rp_id = "ssh:mybox"
            user_name = "ann"

        self.assertEqual(public_label(Credential()), "ssh:mybox (ann)")
        self.assertEqual(describe(Credential()), "[ssh] ssh:mybox (ann)")

    def test_whitespace_is_collapsed_rather_than_preserved(self):
        self.assertEqual(
            public_label({"rp_id": "example.com", "user_name": "  a\t\tb  "}),
            "example.com (a b)",
        )


if __name__ == "__main__":
    unittest.main()
