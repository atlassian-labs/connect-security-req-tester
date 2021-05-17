from jsonobject import IntegerProperty, JsonObject, StringProperty


class HstsResult(JsonObject):
    header = StringProperty()
    max_age = IntegerProperty()
