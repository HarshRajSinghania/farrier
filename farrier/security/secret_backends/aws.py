"""AWS Secrets Manager. The index keeps the secret ARN; the secret name is FARRIER_SECRET_AWS_PREFIX + name.

put: PutSecretValue (a new version), or CreateSecret when the secret does not exist yet (with
FARRIER_SECRET_AWS_KMS_KEY as KmsKeyId when set), or RestoreSecret + PutSecretValue when it is scheduled
for deletion. delete: DeleteSecret with a 7 day recovery window.
"""
from __future__ import annotations

import os
import re
import uuid

from farrier.security.cloud_auth import aws
from farrier.security.cloud_auth.http import CloudConfigError, CloudError
from farrier.security.secret_backends import CachedBackend

ARN = re.compile(r"^arn:aws[a-z-]*:secretsmanager:(?P<region>[a-z0-9-]+):\d{12}:secret:(?P<name>[A-Za-z0-9/_+=.@-]+)$")
NAME = re.compile(r"^[A-Za-z0-9/_+=.@-]{1,512}$")
RECOVERY_DAYS = 7


class AwsSecretsManager(CachedBackend):
    name = "aws"
    scheme = "aws-sm"

    def __init__(self, store=None, *, strict: bool = True, env=None, http=None, creds=None):
        super().__init__()
        env = os.environ if env is None else env
        self.prefix = env.get("FARRIER_SECRET_AWS_PREFIX", "farrier/")
        self.kms_key = env.get("FARRIER_SECRET_AWS_KMS_KEY") or None
        self.http = http
        self.creds = creds or (aws.default_provider() if env is os.environ else aws.AwsCredentialProvider(env, http))
        try:
            self.region = aws.region_for("FARRIER_SECRET_AWS_REGION", env.get("FARRIER_SECRET_AWS_REGION"), env)
        except CloudConfigError:
            if strict:
                raise
            self.region = None
        if not NAME.match(self.prefix + "x"):
            raise CloudConfigError("FARRIER_SECRET_AWS_PREFIX may only use A-Z a-z 0-9 / _ + = . @ -")

    @staticmethod
    def parse(ref: str) -> tuple[str | None, str]:
        """(region from the ARN or None, secret name)."""
        m = ARN.match(ref)
        if m:
            return m["region"], m["name"]
        if NAME.match(ref):
            return None, ref
        raise ValueError("aws-sm reference must be a Secrets Manager secret ARN or name")

    def _call(self, target: str, payload: dict, region: str | None = None) -> dict:
        region = region or self.region
        if not region:
            raise CloudConfigError("FARRIER_SECRET_AWS_REGION is not set (nor AWS_REGION)")
        return aws.json_call("secretsmanager", target, payload, region=region, creds=self.creds, http=self.http,
                             what=f"AWS Secrets Manager {target}")

    def _store(self, name: str, value: str) -> str:
        sid = self.prefix + name
        put = {"SecretId": sid, "SecretString": value, "ClientRequestToken": str(uuid.uuid4())}
        try:
            return self._call("PutSecretValue", put)["ARN"]
        except CloudError as e:
            if e.code == "ResourceNotFoundException":
                create = {"Name": sid, "SecretString": value, "ClientRequestToken": put["ClientRequestToken"],
                          "Description": "Managed by Farrier"}
                if self.kms_key:
                    create["KmsKeyId"] = self.kms_key
                return self._call("CreateSecret", create)["ARN"]
            if e.code == "InvalidRequestException" and "delet" in str(e).lower():
                self._call("RestoreSecret", {"SecretId": sid})
                return self._call("PutSecretValue", put)["ARN"]
            raise

    def _fetch(self, ref: str) -> str | None:
        region, _ = self.parse(ref)
        try:
            j = self._call("GetSecretValue", {"SecretId": ref}, region)
        except CloudError as e:
            if e.code == "ResourceNotFoundException":
                return None
            raise
        return j.get("SecretString")

    def _remove(self, ref: str) -> None:
        region, _ = self.parse(ref)
        try:
            self._call("DeleteSecret", {"SecretId": ref, "RecoveryWindowInDays": RECOVERY_DAYS}, region)
        except CloudError as e:
            if e.code != "ResourceNotFoundException":
                raise

    def describe(self) -> dict:
        return {"kind": "aws", "location": f"AWS Secrets Manager {self.region or '(region not set)'}, "
                                           f"prefix {self.prefix}"}

    def owns(self, body: str) -> bool:
        region, name = self.parse(body)
        return name.startswith(self.prefix) and (region is None or self.region is None or region == self.region)
