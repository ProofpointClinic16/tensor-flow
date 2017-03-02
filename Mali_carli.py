import re
from copy import deepcopy


def parse(filename):
    data = []
    some_num = 1000
    samples = []
    malicious_data = []
    malicious_samples = []
    malicious_count = 0

    with open(filename) as f:
        count = 0
        for line in f:
            datum = {}

            result = re.search(r"result': u'(.+?)'}", line).group(1)
            url = re.search(r"url': u'(.+?)', ", line).group(1)
            ip = re.search(r"ip': u'(.+?)', ", line).group(1)

            # Our regex is imperfect
            # Temporary workaround: ignore things that don't parse correctly
            if result != 'malicious' and result != 'clean':
                continue

            datum['url'] = url
            datum['result'] = result
            datum['ip'] = ip

            datum['urlIP'] = url + "." + ip

            if result == 'malicious':
                malicious_data += [datum]
                malicious_count += 1

                if malicious_count > 3*some_num/4:
                    malicious_data = malicious_data[1:]
                    
            data += [datum]

            #increment count until we have some_num amount (1000)
            count += 1
            
            #once we have 1000, we add it to our list of data samples
            if count == some_num:
                samples += [data]
                malicious_set = deepcopy(malicious_data)
                malicious_samples += [malicious_set]
                count = 0
                data = []
        
        #might have to change this
        if len(data) != 0:
            samples += [data]




    return (samples, malicious_samples)
