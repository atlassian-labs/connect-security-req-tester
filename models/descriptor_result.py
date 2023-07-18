from jsonobject import (DefaultProperty, DictProperty, JsonObject,
                        ListProperty, StringProperty)


class DescriptorLink(JsonObject):
    cache_header = StringProperty()
    referrer_header = StringProperty()
    session_cookies = ListProperty(StringProperty())
    auth_header = StringProperty()
    req_method = StringProperty()
    res_code = StringProperty()
    response = StringProperty()


class DescriptorResult(JsonObject):
    key = StringProperty()
    name = StringProperty()
    base_url = StringProperty()
    app_descriptor_url = StringProperty()
    app_descriptor = DefaultProperty()
    scopes = ListProperty(StringProperty())
    links = ListProperty(StringProperty())
    link_errors = DictProperty()
    scan_results = DictProperty(DescriptorLink)
    response = StringProperty()
