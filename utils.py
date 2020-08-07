KEY_IGNORELIST = ['icon', 'icons', 'documentation']


def get_vals_from_nested_dict(nested_dict):
    res = []
    for key, value in nested_dict.items():
        if key in KEY_IGNORELIST:
            continue
        if type(value) is dict:
            res.extend(get_vals_from_nested_dict(value))
        if key == 'url':
            res.extend([value])

    return res


def find_url_in_module(module):
    urls = []
    if type(module) is list:
        for item in module:
            urls.extend(get_vals_from_nested_dict(item))
    else:
        urls.extend(get_vals_from_nested_dict(module))

    return urls
