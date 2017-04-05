import json
import re
from copy import deepcopy


def parse(filename, bayesfilename):
    data = []
    some_num = 1000
    samples = []
    malicious_data = []
    malicious_samples = []
    malicious_count = 0

    # Grab
    with open(bayesfilename) as bayes_file:
        bayesArray = json.load(bayes_file)

    with open(filename) as f:
        count = 0
        index = 0

        # We go through our data 
        for line in f:
            datum = {}

            result = re.search(r"result': u'(.+?)'}", line).group(1)
            url = re.search(r"url': u'(.+?)', ", line).group(1)
            ip = re.search(r"ip': u'(.+?)', ", line).group(1)

            # finalIP = ""
            # octets = ip.split('.')
            
            # # 
            # for octet in octets:
            #     lengthOct = len(octet)
            #     if lengthOct < 3:
            #         finalIP += (3-lengthOct)*"0" + octet
            #     else:
            #         finalIP += octet    

            # Ignores urls with result other than "malicious" or "clean"
            if result != 'malicious' and result != 'clean':
                continue

            # We convert any potentialy scientific number into a float
            # We remove the decimal punctuation

            datum['url'] = url
            datum['result'] = result
            datum['ip'] = ip

            datum['urlIP'] = url + "." + ip

            # Check if our probability from Bayes is 1
            # If so, we append only 1
            # Else, we append only what would be on the right of the decimal
            # if bayesResult[0] == '1':
            #     datum['urlIP_Bayes'] = datum['urlIP'] + ".1"
            # else:
            if(index == 1000):
                index = 0

            floatBResult = bayesArray[index][0]
            strBResult = str(floatBResult)
            bayesResult = strBResult.replace('.', '')
            bayesResult = bayesResult.replace('-', '')
            datum['urlIP_Bayes'] = bayesResult  + "." + datum['url']

            if result == 'malicious':
                malicious_data += [datum]
                malicious_count += 1

                if malicious_count > 3*some_num/4:
                    malicious_data = malicious_data[1:]
                    
            data += [datum]

            # Increment count until we have some_num amount (1000)
            # Also Increment index so we move along our bayesArray
            count += 1
            index += 1

            # Once we have some_num, we add the data to our list of samples
            if count == some_num:
                samples += [data]
                malicious_set = deepcopy(malicious_data)
                malicious_samples += [malicious_set]
                count = 0
                data = []
        
        #might have to change this
        # if len(data) != 0:
        #     samples += [data]

    return (samples, malicious_samples)
