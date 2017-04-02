import re
from copy import deepcopy


def parse(filename, bayes):
    data = []
    some_num = 1000
    samples = []
    malicious_data = []
    malicious_samples = []
    malicious_count = 0

    with open(filename) as f:
        count = 0
        index = 0

        # We go through our data 
        for line in f:
            datum = {}

            result = re.search(r"result': u'(.+?)'}", line).group(1)
            url = re.search(r"url': u'(.+?)', ", line).group(1)
            ip = re.search(r"ip': u'(.+?)', ", line).group(1)

            finalIP = ""
            octets = ip.split('.')
            

            for octet in octets:
                lengthOct = len(octet)
                if lengthOct < 3:
                    finalIP += (3-lengthOct)*"0" + octet
                else:
                    finalIP += octet    

            # Ignores urls with result other than "malicious" or "clean"
            if result != 'malicious' and result != 'clean':
                continue

            floatBResult = float(bayes[count][0])
            bayesResult = floatBResult.split('.')

            datum['url'] = url
            datum['result'] = result
            datum['ip'] = finalIP

            datum['urlIP'] = url + "." + ip
            datum['urlIP_Bayes'] = datum['urlIP'] + "." + bayesResult[1]

            if result == 'malicious':
                malicious_data += [datum]
                malicious_count += 1

                if malicious_count > 2*some_num/3:
                    malicious_data = malicious_data[1:]
                    
            data += [datum]

            # Increment count until we have some_num amount (1000)
            count += 1
            
            # Once we have some_num, we add the data to our list of samples
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
