#!/usr/bin/env python3
""" Auth Class """

from flask import request
from typing import List, TypeVar


class Auth:
    """ Auth Class """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Require auth method """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        for i in range(len(excluded_paths)):
            if excluded_paths[i].rstrip('/') == path.rstrip('/'):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Authorization header method """
        if request is None:
            return None
        if "Authorization" in request.headers:
            return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar('User'):
        """ Current user method """
        return None
