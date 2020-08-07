from jsonobject import JsonObject, StringProperty, ListProperty, DefaultProperty, IntegerProperty, BooleanProperty, DictProperty


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
