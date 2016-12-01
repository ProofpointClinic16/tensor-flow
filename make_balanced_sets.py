import re
from pprint import pprint

# Size is the total number of samples in one data set
def create_sets(filename, size=10):

    data = []

    #Code has to be changed a bit below, such as size since for TFlow we don't need to create a training and testing
    #set on our own. Consequently, the following code will be rewritten to be more clear. Direct questions to Kevin.
    malicious_training = clean_training = malicious_testing = clean_testing = size/2

    with open(filename) as f:
        for line in f:

            datum = {}

            result = re.search(r"result': u'(.+?)'}", line).group(1)
            url = re.search(r"url': u'(.+?)', ", line).group(1)

            datum['url'] = url
            datum['result'] = result

            if result == 'malicious' and malicious_training > 0:
                data += [datum]
                malicious_training -= 1
            elif result == 'clean' and clean_training > 0:
                data += [datum]
                clean_training -= 1
            elif result == 'malicious' and malicious_testing > 0:
                data += [datum]
                malicious_testing -= 1
            elif result == 'clean' and clean_testing > 0:
                data += [datum]
                clean_testing -= 1

            if malicious_training == 0 and clean_training == 0 and malicious_testing == 0 and clean_testing == 0:
                break

    return data
