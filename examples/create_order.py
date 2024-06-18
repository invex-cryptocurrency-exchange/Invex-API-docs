import binascii
import datetime
import json
import uuid

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key


class TradingAPI:
    def __init__(self):
        self._base_url = "https://invex.ir"
        self._private_key = "PRIVATE_KEY_HERE"
        self.api_key = "API_KEY_HERE"
        self.headers = {'X-API-Key-Invex': self.api_key}

    def sign_using_private_key(self, content):
        message = json.dumps(content)
        byte_private_key = binascii.unhexlify(self._private_key)
        rsa_private_key = load_der_private_key(byte_private_key, password=None)
        signature = rsa_private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()

    def create_order(self):
        expire_at = (datetime.datetime.now() + datetime.timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S")
        params = {
            "quantity": "10",
            "price": "0.1",
            "symbol": "TRX_USDT",
            "side": "BUYER",
            "type": "LIMIT",
            "client_order_id": str(uuid.uuid4()),
            "expire_at": expire_at,
        }

        params["signature"] = self.sign_using_private_key(params)
        response = json.loads(
            requests.post(
                url=f'{self._base_url}/trading/v1/orders',
                data=json.dumps(params),
                headers=self.headers
            ).content
        )

        return response


if __name__ == '__main__':
    api = TradingAPI()
    print(api.create_order())
