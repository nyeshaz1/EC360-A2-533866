import unittest
from auth_service import register_user, verify_password


class TestAuth(unittest.TestCase):

    def test_successful_registration(self):
        result = register_user("user@example.com", "SecurePass123")
        self.assertTrue(result["success"])
        self.assertIn("password_hash", result)
        self.assertNotEqual(result["password_hash"], "SecurePass123")

    def test_invalid_email(self):
        result = register_user("invalid-email", "SecurePass123")
        self.assertFalse(result["success"])

    def test_short_password(self):
        result = register_user("user@example.com", "short")
        self.assertFalse(result["success"])

    def test_password_verification(self):
        result = register_user("user@example.com", "SecurePass123")
        self.assertTrue(
            verify_password("SecurePass123", result["password_hash"])
        )
        self.assertFalse(
            verify_password("WrongPassword", result["password_hash"])
        )


if __name__ == "__main__":
    unittest.main()
