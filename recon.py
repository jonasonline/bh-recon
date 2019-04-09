import json, os, subprocess, shutil

firstRun = True
with open('programs.json') as programsFile:
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
                    print(target['domain'])
                    domainBase = target['domain'].replace('*.','')
                    arguments = '-d ' + domainBase + ' -json ./output/' + programName + '/amass/' + domainBase + '.json -log ./output/' + programName + '/amass/' + domainBase + '.log.txt -do ./output/' + programName + '/amass/' + domainBase + '_data.json'
                    print(arguments)
                    #subprocess.run('amass ' + arguments, shell=True)
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
        with open('./output/' + programName + '/sortedDomains.json', 'r') as current:
            currentData = json.load(current)
            currentDataSet = set(currentData)
            with open('./output/' + programName + '/sortedDomains.json.old', 'r') as old:
                oldData = json.load(old)
                oldDataSet = set(oldData)
                for domain in currentDataSet:
                    if domain not in oldDataSet and firstRun == False:
                        print('New domain for ' + programName + ': ' + domain)



        

        #with open('amass_output/data.json') as amassOut:
        #    for line in amassOut:
        #    output = json.loads(line)
                    



        
    
