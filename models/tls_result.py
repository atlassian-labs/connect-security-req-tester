from jsonobject import (BooleanProperty, DefaultProperty, IntegerProperty,
                        JsonObject, ListProperty, StringProperty)


class TlsResult(JsonObject):
    ips_scanned = IntegerProperty()
    protocols = ListProperty(StringProperty())
    trusted = BooleanProperty()
    scan_results = DefaultProperty()
    domain = StringProperty()
