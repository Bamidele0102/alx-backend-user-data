#!/usr/bin/env python3
"""API authentication module."""

from flask import request
from typing import List, TypeVar

User = TypeVar('User')


class Auth:
    """Authentication Object. Task: 4"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checks if API routes require authentication. Task 12('*')"""
        if path is None or not excluded_paths:
            return True
        for i in excluded_paths:
            if i.endswith('*') and path.startswith(i[:-1]):
                return False
            elif i in {path, path + '/'}:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Checks if Authorization request header
        is present& valid. Task 5
        """
        if request is None or "Authorization" not in request.headers:
            return None
        else:
            return request.headers.get('Authorization')

    def current_user(self, request=None) -> User:
        """Current user instance."""
        return None
