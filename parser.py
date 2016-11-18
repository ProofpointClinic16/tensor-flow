import re


def parse(filename):
    data = []

    with open(filename) as f:
        for line in f:

            datum = {}

            result = re.search(r"result': u'(.+?)'}", line).group(1)
            url = re.search(r"url': u'(.+?)', ", line).group(1)

            # Our regex is imperfect
            # Temporary workaround: ignore things that don't parse correctly
            if result != 'malicious' and result != 'clean':
                continue

            datum['url'] = url
            datum['result'] = result

            data += [datum]

    return data

