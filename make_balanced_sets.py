import re
from pprint import pprint

# Size is the total number of samples in one data set
def create_sets(filename, size=10):

    training = []
    testing = []

    malicious_training = clean_training = malicious_testing = clean_testing = size/2

    with open(filename) as f:
        for line in f:

            datum = {}

            result = re.search(r"result': u'(.+?)'}", line).group(1)
            url = re.search(r"url': u'(.+?)', ", line).group(1)

            datum['url'] = url
            datum['result'] = result

            if result == 'malicious' and malicious_training > 0:
                training += [datum]
                malicious_training -= 1
            elif result == 'clean' and clean_training > 0:
                training += [datum]
                clean_training -= 1
            elif result == 'malicious' and malicious_testing > 0:
                testing += [datum]
                malicious_testing -= 1
            elif result == 'clean' and clean_testing > 0:
                testing += [datum]
                clean_testing -= 1

            if malicious_training == 0 and clean_training == 0 and malicious_testing == 0 and clean_testing == 0:
                break

    #pprint([training, testing])

    return [training, testing]
