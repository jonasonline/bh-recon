import json, os, subprocess, shutil

firstRun = True
with open('programs.temp.json') as programsFile:
    programs = json.load(programsFile)
    
    for program in programs['programs']:
        uniqueDomains = set([])
        programName = program['programName']
        amassFolder = './output/' + programName + '/amass'
        os.makedirs(amassFolder, exist_ok=True, )
        #Saving old files for comparison 
        for filename in os.listdir(amassFolder):
            if not filename.endswith('.old'):
                shutil.copy(amassFolder + '/' + filename, amassFolder + '/' + filename + '.old')
        for target in program['scope']:
            if target['inScope'] == True:
                if 'url' in target:
                    print('Nothing to do here')
                elif 'domain' in target:
                    domainBase = target['domain'].replace('*.','')
                    
                    #run amass
                    arguments = '-d ' + domainBase + ' -json ./output/' + programName + '/amass/' + domainBase + '.json -log ./output/' + programName + '/amass/' + domainBase + '.log.txt -do ./output/' + programName + '/amass/' + domainBase + '_data.json'
                    print(arguments)
                    subprocess.run('amass ' + arguments, shell=True)

                    #run subfinder
                    subfinderArguments = '-d ' + domainBase + ' -o ./output/' + programName + '/subfinder/' + domainBase + '.json -oJ -t 10 -v -b -w ../wordlists/subdomains/jhaddix_all.txt -r 1.1.1.1, 8.8.8.8' 
                    subprocess.run('./subfinder ' + arguments, shell=True)


        #Processing unique names
        for filename in os.listdir(amassFolder):
            if filename.endswith('.json') and not filename.endswith('_data.json'):
                with open(amassFolder + '/' + filename) as amassOut:
                    for line in amassOut:
                        try:    
                            output = json.loads(line)
                            uniqueDomains.add(output['name'])
                        except:
                            print('Error')
        if os.path.isfile('./output/' + programName + '/sortedDomains.json'):
            firstRun = False
            shutil.copy('./output/' + programName + '/sortedDomains.json', './output/' + programName + '/sortedDomains.json.old')
        with open('./output/' + programName + '/sortedDomains.json', 'w') as f:
            json.dump(sorted(uniqueDomains), f)

        #compare old and new current domains
        if os.path.isfile('./output/' + programName + '/sortedDomains.json.old'):
            with open('./output/' + programName + '/sortedDomains.json', 'r') as current:
                currentData = json.load(current)
                currentDataSet = set(currentData)
                with open('./output/' + programName + '/sortedDomains.json.old', 'r') as old:
                    oldData = json.load(old)
                    oldDataSet = set(oldData)
                    for domain in currentDataSet:
                        if domain not in oldDataSet and firstRun == False:
                            print('New domain for ' + programName + ': ' + domain)
            
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