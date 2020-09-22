from jsonobject import (BooleanProperty, DefaultProperty, DictProperty,
                        IntegerProperty, JsonObject, ListProperty,
                        StringProperty)


class IpResult(JsonObject):
    protocols = ListProperty(StringProperty())
    hsts = DefaultProperty()
    cert_grade = StringProperty()


class TlsResult(JsonObject):
    ips_scanned = IntegerProperty()
    protocols = ListProperty(StringProperty())
    hsts_present = BooleanProperty()
    trusted = BooleanProperty()
    scan_results = DictProperty(IpResult)
