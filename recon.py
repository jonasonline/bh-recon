import json, os, subprocess, shutil, requests

def postToSlack(webhookURL, message):
    requests.post(webhookURL, json={"text":message})

with open('config.json', 'r') as configFile:
    config = json.load(configFile)

with open('programs.json') as programsFile:
    programs = json.load(programsFile)
    
    for program in programs['programs']:
        if program['enabled'] == False:
            continue
        firstRun = True
        uniqueDomains = set([])
        programName = program['programName']
        amassFolder = './output/' + programName + '/amass'
        subfinderFolder = './output/' + programName + '/subfinder'
        masscanFolder = './output/' + programName + '/masscan'
        digFolder = './output/' + programName + '/dig'
        gobusterFolder = './output/' + programName + '/gobuster'
        os.makedirs(amassFolder, exist_ok=True, )
        os.makedirs(subfinderFolder, exist_ok=True, )
        os.makedirs(masscanFolder, exist_ok=True, )
        os.makedirs(digFolder, exist_ok=True, )
        os.makedirs(gobusterFolder, exist_ok=True, )
                    
        for target in program['scope']:
            if target['inScope'] == True:
                if 'url' in target:
                    print(target['url'] + ': No URL Processing implemented.')
                elif 'domain' in target:
                    domainBase = target['domain'].replace('*.','')
                    
                    #Saving old files for comparison 
                    amassDomainFolder = amassFolder + "/" + domainBase
                    if os.path.isdir(amassDomainFolder):
                        for filename in os.listdir(amassDomainFolder):
                            if not filename.endswith('.old'):
                                shutil.copy(amassDomainFolder + '/' + filename, amassDomainFolder + '/' + filename + '.old')

                    #run amass
                    amassArguments = '-active -d ' + domainBase + ' -dir ./output/' + programName + '/amass/' + domainBase + '/'
                    print(amassArguments)
                    #subprocess.run('amass enum ' + amassArguments, shell=True)

                    #run subfinder
                    subfinderOutputFolder = './output/' + programName + '/subfinder/'
                    if not os.path.exists(subfinderOutputFolder):
                        os.makedirs(subfinderOutputFolder)
                    subfinderArguments = '-d ' + domainBase + ' -o ./output/' + programName + '/subfinder/' + domainBase + '.json -oJ -t 10 -v -b -w ./wordlists/subdomains/jhaddix_all.txt -r 1.1.1.1, 8.8.8.8' 
                    print(subfinderArguments)
                    #subprocess.run('~/go/bin/subfinder ' + subfinderArguments, shell=True)

                    #Processing unique names
                    #Amass unique names
                    for filename in os.listdir(amassDomainFolder):
                        if filename.endswith('.json') and not filename.endswith('_data.json'):
                            with open(amassDomainFolder + '/' + filename) as amassOut:
                                for line in amassOut:
                                    try:    
                                        output = json.loads(line)
                                        uniqueDomains.add(output['name'])
                                    except:
                                        print('Error')
                    #Subfinder unique names
                    for filename in os.listdir(subfinderOutputFolder):
                        if filename.endswith('.json'):
                            with open(subfinderOutputFolder + '/' + filename) as subfinderOut:
                                output = json.load(subfinderOut)
                                for domain in output:    
                                    try:    
                                        sanitizedDomain = domain.lstrip('.')
                                        print(sanitizedDomain)
                                        uniqueDomains.add(sanitizedDomain)        
                                    except:
                                        print('Error')
                    

        #compare old and new current domains
        if os.path.isfile('./output/' + programName + '/sortedDomains.json'):
            firstRun = False
            shutil.copy('./output/' + programName + '/sortedDomains.json', './output/' + programName + '/sortedDomains.json.old')
        with open('./output/' + programName + '/sortedDomains.json', 'w') as f:
            json.dump(sorted(uniqueDomains), f)
        if os.path.isfile('./output/' + programName + '/sortedDomains.json.old'):
            with open('./output/' + programName + '/sortedDomains.json', 'r') as current:
                currentData = json.load(current)
                currentDataSet = set(currentData)
                with open('./output/' + programName + '/sortedDomains.json.old', 'r') as old:
                    oldData = json.load(old)
                    oldDataSet = set(oldData)
                    for domain in currentDataSet:
                        if domain not in oldDataSet and firstRun == False:
                            message = 'New domain for ' + programName + ': ' + domain
                            print(message)
                            postToSlack(config["slackWebhookURL"], message)
            
        #add domains to incremental domain list
        with open('./output/' + programName + '/sortedDomains.json', 'r') as current:
            currentData = json.load(current)
            currentDataSet = set(currentData)
            with open('./output/' + programName + '/incrementalDomains.txt', 'a+') as inc:
                inc.seek(0)
                incDomains = set(line.strip() for line in inc)
                for domain in currentDataSet:
                    if domain not in incDomains:
                        print('Adding domain ' + domain + ' to incremental list for ' + programName)
                        inc.write("%s\n" % domain)