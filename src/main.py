from base64 import urlsafe_b64encode
import json
import hmac
import hashlib


def to_base64(data):
    data_type = json.dumps(data).encode()
    encoded = urlsafe_b64encode(data_type)
    return encoded


header = {"alg": "HS256", "typ": "JWT"}  # 署名アルゴリズム  # タイプ（JWT固定)

payload = {
    "iat": 1653199095,  # jwtを発行した時刻
    "jti": "da5dd8a6-15c5-4197-9f6b-cc0f6051dcf2",
    "type": "access",
    "sub": "U0000000120",  # 許可した対象の一意な識別子(ユーザーIDなど)
    "nbf": 1653199095,  # nbf jwtが有効になる時刻
    "exp": 1653199995,  # jwtの有効期限
}

header_base64 = to_base64(header).decode()
payload_base64 = to_base64(payload).decode()
secret_key = b"Secret Keeeeeeeeeeeeeeeeeeeey"

no_signature = header_base64 + "." + payload_base64

signature_bytes = urlsafe_b64encode(
    hmac.new(secret_key, no_signature.encode(), hashlib.sha256).digest()
)

signature = signature_bytes.decode().rstrip("=")

jwt = header_base64 + "." + payload_base64 + "." + signature
print(jwt)

signatured_header, signatured_payload = jwt.split(".")
