from configparser import ConfigParser
from pathlib import Path
import requests
from cryptography.x509 import load_pem_x509_csr, ExtendedKeyUsage
from cryptography.x509.oid import ExtendedKeyUsageOID
from typing import Optional
from .base import Backend
from ..challenge import SimpleIdentifier

class CcpkiBackend(Backend):
    api_url: str
    ca_path: Path
    cert_path: Path
    key_path: Path
    timeout: float

    def __init__(self, config: ConfigParser):
        self.api_url = config["ccpki"]["apiUrl"]
        self.ca_path = config["ccpki"]["caPath"]
        self.cert_path = config["ccpki"]["certPath"]
        self.key_path = config["ccpki"]["keyPath"]
        self.timeout = config.getfloat("ccpki", "timeout", fallback=1.0)

    def get_requests_session(self):
        session = requests.Session()
        session.verify = self.ca_path
        session.cert = (self.cert_path, self.key_path)
        return session

    def get_profile(csr: bytes) -> str:
        csr_obj = load_pem_x509_csr(csr)
        ext_usage = csr_obj.extensions.get_extension_for_class(ExtendedKeyUsage)
        usage_oids = list(ext_usage.value)
        if ExtendedKeyUsageOID.SERVER_AUTH in usage_oids:
            return "server"
        elif ExtendedKeyUsageOID.CLIENT_AUTH in usage_oids:
            return "client"
        else:
            return "server"

    def sign(self,
        csr: bytes,
        subjectDN: str,
        subjectAltNames: list[SimpleIdentifier],
        email: str
    ) -> tuple[bytes | str | None, Optional[str]]:
        try:
            session = self.get_requests_session()
            url = self.api_url + "/api/v1/sign"
            response = session.post(
                url,
                json={
                    "csr": csr.decode("utf-8"),
                    "profile": self.get_profile(csr),
                },
                timeout=self.timeout,
            )
            if response.status_code >= 400:
                try:
                    error_message = response.json().get("message")
                except:
                    error_message = "Unknown error"
                return None, f"Request failed with status code {response.status_code}: {error_message}"
            elif (response.status_code == 201
                and response.headers.get("Content-Type") == "application/x-pem-file"
            ):
                return response.content, None
            else:
                return None, f"Unknown response: {response.status_code} {response.text}"
        except requests.RequestException as e:
            return None, f"Request failed: {e}"
        except Exception as e:
            return None, f"Unexpected error: {e}"
