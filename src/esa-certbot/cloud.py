"""Pinned Alibaba Cloud SDK adapters. No credential-chain or local AK fallback."""
from alibabacloud_tea_openapi.models import Config
from alibabacloud_tea_util.models import RuntimeOptions
from alibabacloud_esa20240910.client import Client as ESA
from alibabacloud_esa20240910 import models as e
from alibabacloud_cas20200407.client import Client as CAS
from alibabacloud_cas20200407 import models as c
from alibabacloud_fc20230330.client import Client as FC
from alibabacloud_fc20230330 import models as f
from state import Failure


class Cloud:
    def __init__(self, credentials, account, target):
        if not all(credentials.get(k) for k in ("access_key_id", "access_key_secret", "security_token")):
            raise Failure("FC_ROLE_STS_REQUIRED")
        if not str(account).isdigit():
            raise Failure("FC_ACCOUNT_REQUIRED")
        self.target = target
        def config(endpoint):
            return Config(**credentials, endpoint=endpoint, connect_timeout=5000, read_timeout=15000)
        self.esa = ESA(config("esa." + target["esa_region"] + ".aliyuncs.com"))
        self.cas = CAS(config("cas.aliyuncs.com"))
        self.fc = FC(config(str(account) + "." + target["region"] + ".fc.aliyuncs.com"))
        # Mutations must not be silently retried by the SDK.
        self.runtime = RuntimeOptions(autoretry=False, max_attempts=1)

    def validate_site(self):
        site = self.esa.get_site_with_options(e.GetSiteRequest(
            site_id=self.target["site_id"]), self.runtime).body.site_model
        nameservers = {n.strip().rstrip(".").lower() for n in (site.name_server_list or "").split(",")}
        if (site.site_id != self.target["site_id"] or site.site_name != self.target["zone"]
                or site.access_type != "NS" or site.status != "active"
                or nameservers != set(self.target["nameservers"])):
            raise Failure("ESA_SITE_SCOPE_MISMATCH")

    def records(self, name):
        out = []
        for page in range(1, 101):
            result = self.esa.list_records_with_options(e.ListRecordsRequest(
                site_id=self.target["site_id"], record_name=name, record_match_type="exact",
                type="TXT", page_number=page, page_size=500), self.runtime).body
            for r in result.records or []:
                out.append({"id": r.record_id, "name": r.record_name, "type": r.record_type,
                            "value": r.data.value if r.data else None, "comment": r.comment,
                            "site_id": r.site_id})
            if page * 500 >= result.total_count:
                return out
        raise Failure("DNS_PAGE_LIMIT")

    def create_txt(self, name, value, comment):
        self.validate_site()
        return self.esa.create_record_with_options(e.CreateRecordRequest(
            site_id=self.target["site_id"], record_name=name, type="TXT", ttl=60,
            proxied=False, data=e.CreateRecordRequestData(value=value), comment=comment), self.runtime).body.record_id

    def delete_txt(self, record_id):
        self.esa.delete_record_with_options(e.DeleteRecordRequest(record_id=record_id), self.runtime)

    def find_cert(self, name):
        for page in range(1, 101):
            result = self.cas.list_user_certificate_order_with_options(c.ListUserCertificateOrderRequest(
                order_type="UPLOAD", current_page=page, show_size=100), self.runtime).body
            for cert in result.certificate_order_list or []:
                if cert.name == name:
                    detail = self.cas.get_user_certificate_detail_with_options(
                        c.GetUserCertificateDetailRequest(cert_id=cert.certificate_id), self.runtime).body
                    return {"id": cert.certificate_id, "cert": detail.cert, "key": detail.key}
            if page * 100 >= result.total_count:
                return None
        raise Failure("CAS_PAGE_LIMIT")

    def upload(self, name, cert, key, token):
        return self.cas.upload_user_certificate_with_options(c.UploadUserCertificateRequest(
            name=name, cert=cert, key=key, client_token=token), self.runtime).body.cert_id

    def domain(self):
        body = self.fc.get_custom_domain_with_options(self.target["domain"], {}, self.runtime).body
        cert = body.cert_config
        return {"protocol": body.protocol, "name": cert.cert_name if cert else None,
                "cert": cert.certificate if cert else None}

    def install(self, name, cert, key):
        # Do not replay route/protocol/auth fields read earlier: they may change concurrently.
        request = f.UpdateCustomDomainRequest(body=f.UpdateCustomDomainInput(
            cert_config=f.CertConfig(cert_name=name, certificate=cert, private_key=key)))
        self.fc.update_custom_domain_with_options(self.target["domain"], request, {}, self.runtime)
