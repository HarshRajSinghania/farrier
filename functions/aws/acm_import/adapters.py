"""Thin boto3 adapters for the acm_import ports.

No decisions here: each method is one AWS call (or one paginated listing) plus
error translation (``farrier_aws.aws_call``). The Secrets Manager adapter is
shared with notify_router and lives in ``farrier_aws``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from farrier_aws import aws_call
from farrier_events import PermanentError, S3ObjectRef

MAX_CHAIN_BYTES = 64 * 1024
_ALL_KEY_TYPES = ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]


class S3ChainStore:
    def __init__(self, client: Any) -> None:
        self._s3 = client

    def get_text(self, ref: S3ObjectRef) -> str:
        with aws_call("s3:GetObject"):
            resp = self._s3.get_object(Bucket=ref.bucket, Key=ref.key)
            if int(resp.get("ContentLength", 0)) > MAX_CHAIN_BYTES:
                raise PermanentError("chain object is larger than 64 KiB")
            body = resp["Body"].read(MAX_CHAIN_BYTES + 1)
        try:
            return body.decode("ascii")
        except UnicodeDecodeError:
            raise PermanentError("chain object is not ASCII PEM") from None


class AcmAdapter:
    def __init__(self, client: Any) -> None:
        self._acm = client

    def find_by_endpoint(self, endpoint_id: int) -> str | None:
        """The Farrier-managed certificate tagged with this endpoint id, if any.

        ACM cannot filter by tag, so this lists certificates and reads tags. Fine
        for the hundreds of certificates a typical account holds; set
        ``ACM_DISCOVERY=false`` and use ``acm:<arn>`` tags if that is too slow.
        """
        wanted = str(endpoint_id)
        with aws_call("acm:ListCertificates"):
            pages = self._acm.get_paginator("list_certificates").paginate(Includes={"keyTypes": _ALL_KEY_TYPES})
            for page in pages:
                for summary in page.get("CertificateSummaryList", []):
                    if summary.get("Type", "IMPORTED") != "IMPORTED":
                        continue
                    arn = summary["CertificateArn"]
                    tags = self.get_tags(arn)
                    if tags.get("farrier:managed") == "true" and tags.get("farrier:endpoint-id") == wanted:
                        return str(arn)
        return None

    def get_tags(self, arn: str) -> dict[str, str]:
        with aws_call("acm:ListTagsForCertificate"):
            resp = self._acm.list_tags_for_certificate(CertificateArn=arn)
        return {t["Key"]: t.get("Value", "") for t in resp.get("Tags", [])}

    def import_certificate(
        self, *, certificate: str, private_key: str, chain: str, arn: str | None, tags: Mapping[str, str] | None
    ) -> str:
        params: dict[str, Any] = {
            "Certificate": certificate.encode("ascii"),
            "PrivateKey": private_key.encode("ascii"),
        }
        if chain:
            params["CertificateChain"] = chain.encode("ascii")
        if arn:
            params["CertificateArn"] = arn  # re-import: ACM rejects Tags here, they are added separately
        elif tags:
            params["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
        with aws_call("acm:ImportCertificate"):
            resp = self._acm.import_certificate(**params)
        return str(resp["CertificateArn"])

    def add_tags(self, arn: str, tags: Mapping[str, str]) -> None:
        with aws_call("acm:AddTagsToCertificate"):
            self._acm.add_tags_to_certificate(
                CertificateArn=arn, Tags=[{"Key": k, "Value": v} for k, v in tags.items()]
            )
