from jsonobject import (BooleanProperty, JsonObject, ListProperty,
                        ObjectProperty, StringProperty, DictProperty)


class RequirementsResult(JsonObject):
    passed = BooleanProperty(default=False)
    description = ListProperty(StringProperty())
    title = StringProperty()
    proof = ListProperty(StringProperty())

    def was_scanned(self) -> bool:
        return self.passed or bool(self.description and self.title and self.proof)


class Requirements(JsonObject):
    req1 = ObjectProperty(RequirementsResult, name='1')
    req1_2 = ObjectProperty(RequirementsResult, name='1.2')
    req1_4 = ObjectProperty(RequirementsResult, name='1.4')
    req2 = ObjectProperty(RequirementsResult, name='2')
    req3 = ObjectProperty(RequirementsResult, name='3')
    req3_0 = ObjectProperty(RequirementsResult, name='3.0')
    req5 = ObjectProperty(RequirementsResult, name='5')
    req6_2 = ObjectProperty(RequirementsResult, name='6.2')
    req6_3 = ObjectProperty(RequirementsResult, name='6.3')
    req7_2 = ObjectProperty(RequirementsResult, name='7.2')
    req7_3 = ObjectProperty(RequirementsResult, name='7.3')
    req7_4 = ObjectProperty(RequirementsResult, name='7.4')
    req8_1 = ObjectProperty(RequirementsResult, name='8.1')
    req9 = ObjectProperty(RequirementsResult, name='9')
    req10 = ObjectProperty(RequirementsResult, name='10')
    req11 = ObjectProperty(RequirementsResult, name='11')
    req16 = ObjectProperty(RequirementsResult, name='16')


class Results(JsonObject):
    name = StringProperty()
    key = StringProperty()
    base_url = StringProperty()
    app_descriptor_url = StringProperty()
    requirements = ObjectProperty(Requirements)
    tls_scan_raw = StringProperty()
    descriptor_scan_raw = StringProperty()
    errors = DictProperty()
