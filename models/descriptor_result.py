from jsonobject import (BooleanProperty, DefaultProperty, DictProperty,
                        JsonObject, ListProperty, StringProperty)


class DescriptorLink(JsonObject):
    cache_header = StringProperty()
    referrer_header = StringProperty()
    session_cookies = ListProperty(StringProperty())
    fake_jwt = BooleanProperty()
    res_code = StringProperty()


class DescriptorResult(JsonObject):
    key = StringProperty()
    name = StringProperty()
    base_url = StringProperty()
    app_descriptor_url = StringProperty()
    app_descriptor = DefaultProperty()
    scopes = ListProperty(StringProperty())
    links = ListProperty(StringProperty())
    scan_results = DictProperty(DescriptorLink)
