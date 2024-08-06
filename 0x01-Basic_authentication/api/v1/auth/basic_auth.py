#!/usr/bin/env python3
"""Basic API authentication module."""

from api.v1.auth.auth import Auth
from base64 import b64decode
from models.user import User
from typing import TypeVar, Tuple


User = TypeVar('User')


class BasicAuth(Auth):
    """Basic Authentication. Task 6"""

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """Returns Base64 part of Authorization header. Task 7"""
        if authorization_header and isinstance(
                authorization_header,
                str) and authorization_header.startswith("Basic "):
            return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Returns decoded value of base64_authorization_header. Task 8"""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            return b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """Returns user email and pswd from decoded Base64.Task 9 & 12(":")"""
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None
        email, pwd = decoded_base64_authorization_header.split(':', 1)
        return (email, pwd)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> User:
        """
        Return a User instance based on email and password. Task 10
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            user = User.search({'email': user_email})
        except Exception:
            return None
        for u in user:
            if u.is_valid_password(user_pwd):
                return u
        return None
