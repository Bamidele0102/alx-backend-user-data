#!/usr/bin/env python3
"""Encrypting pswds with bcrypt."""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Takes in string arg, converts to unicode
    Returns salted, hashed pswd as bytestring
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
