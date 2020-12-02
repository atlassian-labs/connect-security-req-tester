from jsonobject import (BooleanProperty, JsonObject, ListProperty,
                        ObjectProperty, StringProperty)


class RequirementsResult(JsonObject):
    passed = BooleanProperty(default=False)
    description = ListProperty(StringProperty())
    title = StringProperty()
    proof = ListProperty(StringProperty())

    def was_scanned(self) -> bool:
        return self.passed or bool(self.description and self.title and self.proof)


class Requirements(JsonObject):
    req1 = ObjectProperty(RequirementsResult, name='1')
    req2 = ObjectProperty(RequirementsResult, name='2')
    req3 = ObjectProperty(RequirementsResult, name='3')
    req4 = ObjectProperty(RequirementsResult, name='4')
    req5 = ObjectProperty(RequirementsResult, name='5')
    req6 = ObjectProperty(RequirementsResult, name='6')
    req7 = ObjectProperty(RequirementsResult, name='7')
    req8 = ObjectProperty(RequirementsResult, name='8')
    req9 = ObjectProperty(RequirementsResult, name='9')
    req10 = ObjectProperty(RequirementsResult, name='10')
    req11 = ObjectProperty(RequirementsResult, name='11')
    req12 = ObjectProperty(RequirementsResult, name='12')
    req13 = ObjectProperty(RequirementsResult, name='13')
    req14 = ObjectProperty(RequirementsResult, name='14')
    req15 = ObjectProperty(RequirementsResult, name='15')
    req16 = ObjectProperty(RequirementsResult, name='16')


class Results(JsonObject):
    name = StringProperty()
    key = StringProperty()
    base_url = StringProperty()
    app_descriptor_url = StringProperty()
    requirements = ObjectProperty(Requirements)
    tls_scan_raw = StringProperty()
    descriptor_scan_raw = StringProperty()
    errors = ListProperty(StringProperty())
