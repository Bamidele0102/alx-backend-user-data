#!/usr/bin/env python3
"""
Definition of class BasicAuth
"""
import base64
from typing import Optional, Tuple

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """ Implement Basic Authorization protocol methods. Task 6
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> Optional[str]:
        """
        Extracts the Base64 part of the Authorization header for a Basic
        Authorization. Task 7
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        token = authorization_header.split(" ")[-1]
        return token

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> Optional[str]:
        """
        Decode a Base64-encoded string. Task 8
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded = base64_authorization_header.encode('utf-8')
            decoded = base64.b64decode(decoded)
            return decoded.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Returns user email and password from Base64
        decoded value. Task 9 & 12(":")"
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        email, password = decoded_base64_authorization_header.split(":", 1)
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> Optional[User]:
        """
        Return a User instance based on email and password. Task 10
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({"email": user_email})
            if not users or users == []:
                return None
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
            return None
        except Exception:
            return None
