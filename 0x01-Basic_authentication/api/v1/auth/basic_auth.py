#!/usr/bin/env python3
""" Basic Auth """

from api.v1.auth.auth import Auth
from api.v1.views.users import User
import re
import base64
from typing import TypeVar


class BasicAuth(Auth):
    """ Basic Auth Class"""

    def extract_base64_authorization_header(
        self,
        authorization_header: str
    ) -> str:
        """extract_base64_authorization_header Method"""

        if authorization_header is None or (type(authorization_header) != str):
            return None
        if authorization_header.startswith("Basic ") is False:
            return None
        Base64 = re.split(' ', authorization_header)
        return Base64[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """decode_base64_authorization_header Method"""

        if (base64_authorization_header is None or
                (type(base64_authorization_header) != str)):
            return None
        try:
            decodeBytes = base64.b64decode(base64_authorization_header)
            decodedStr = decodeBytes.decode("utf-8")
            return decodedStr
        except ValueError:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """extract_user_credentials method"""

        if (decoded_base64_authorization_header is None
                or type(decoded_base64_authorization_header) != str):
            return None, None
        if (re.search(':', decoded_base64_authorization_header)):
            res = re.split(':', decoded_base64_authorization_header)
            return res[0], res[1]
        else:
            return None, None

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """user_object_from_credentials method"""

        if type(user_email) != str or user_email is None:
            return None
        if type(user_pwd) != str or user_pwd is None:
            return None
        try:
            user = User.search({"email": user_email})
        except Exception:
            return None
        for u in user:
            if u.is_valid_password(user_pwd):
                return u
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """current_user method"""

        authHeader = self.authorization_header(request)
        base64AuthHeader = self.extract_base64_authorization_header(authHeader)
        decodedAuthHeader = self.decode_base64_authorization_header(
            base64AuthHeader)
        userEmail, userPwd = self.extract_user_credentials(decodedAuthHeader)
        if not userEmail or not userPwd:
            return None
        return self.user_object_from_credentials(userEmail, userPwd)
