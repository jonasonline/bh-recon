import json, os, subprocess, shutil, requests, argparse, datetime, socket
from tld import get_tld

parser = argparse.ArgumentParser(description='Doing recon.')
parser.add_argument('--program', help="Specify a program name ju run that program only.")
parser.add_argument('--nodomainrecon', action='store_const', const=True, help="Skip looking for new sub domains")
parser.add_argument('--noportscan', action='store_const', const=True, help="Skip port scan")
parser.add_argument('--nobanner', action='store_const', const=True, help="Skip banner grabing")
parser.add_argument('--noslack', action='store_const', const=True, help="Skip posting to Slack")
parser.add_argument('--nohttp', action='store_const', const=True, help="Skip http discovery")
parser.add_argument('--nomassdns', action='store_const', const=True, help="Skip massdns discovery")
parser.add_argument('--nowayback', action='store_const', const=True, help="Skip Wayback machine discovery")
parser.add_argument('--nohttprobe', action='store_const', const=True, help="Skip probing for live sites")
parser.add_argument('--nocontent', action='store_const', const=True, help="Skip content discovery")
parser.add_argument('--definedcontentonly', action='store_const', const=True, help="Skip content discovery")
parser.add_argument('--noeyewitness', action='store_const', const=True, help="Skip scrren capture with EyeWitness")

args = parser.parse_args()

def postToSlack(webhookURL, message):
    requests.post(webhookURL, json={"text":message})
def myconverter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()
def runSubfinder(programName, domainBase, outputFolder):
    subfinderArguments = '-d ' + domainBase + ' -o ' + outputFolder + domainBase + '.json -oJ -t 100 -v -b -w ./wordlists/subdomains/jhaddix_all.txt -r 1.1.1.1, 8.8.8.8, 2.2.2.2' 
    #print(subfinderArguments)
    subprocess.run('~/go/bin/subfinder ' + subfinderArguments, shell=True)

def findProbableWildcardDomains(jsonFilePath):
    with open(jsonFilePath) as subOut:
        probableWildcardDomains = set([]) 
        data = subOut.read()
        subOut.seek(0)
        output = json.load(subOut)
        for domain in output:    
            try:    
                sanitizedDomain = domain.lstrip('.')
                res = get_tld("https://" + sanitizedDomain, fail_silently=True, as_object=True)
                baseDomain = res.fld
                subDomains = sanitizedDomain.split("." + baseDomain) 
                subDomains = subDomains[0]
                subDomains = subDomains.split(".")
                subDomains.reverse()
                tryDomain = baseDomain
                for subDomain in subDomains:
                    tryDomain = subDomain + "." + tryDomain
                    if data.count(tryDomain) > 5:
                        probe = "noresult." + tryDomain
                        try:
                            socket.gethostbyname(probe)
                            socket.gethostbyname("testingforwildcard." + tryDomain)
                            socket.gethostbyname("gydjfchvmlvdruiuhcoshlvn." + tryDomain)
                            probableWildcardDomains.add(tryDomain)
                            break
                        except:
                            pass
            except:
                print('Error')
        return probableWildcardDomains

def addContentDomain(inputURLTextFileName):
    with open('./output/' + programName + '/' + inputURLTextFileName, 'r') as inputFile:
            inputFile.seek(0)
            incDomains = set(line.strip() for line in inputFile)
            for domain in incDomains:
                if domain not in incrementalContentDomains:
                    incrementalContentDomains[domain] = {"Added": datetime.datetime.now(), "Status": "Pending"}
            with open('./output/' + programName + '/contentDomains.json', 'w') as contentDomains:
                json.dump(incrementalContentDomains, contentDomains, default = myconverter)

with open('config.json', 'r') as configFile:
    config = json.load(configFile)

with open('programs.json') as programsFile:
    programs = json.load(programsFile)
    for program in programs['programs']:
        if program['enabled'] == False:
            continue
        if args.program and program['programName'] != args.program:
            continue
        
        firstRun = True
        uniqueDomains = set([])
        uniqueURLs = set([])
        programName = program['programName']
        outputFolder = './output/' + programName + ''
        amassFolder = './output/' + programName + '/amass'
        subfinderFolder = './output/' + programName + '/subfinder'
        masscanFolder = './output/' + programName + '/masscan'
        masscanIpListFile = masscanFolder + '/ipList.txt'
        digFolder = './output/' + programName + '/dig'
        gobusterFolder = './output/' + programName + '/gobuster'
        nmapFolder = './output/' + programName + '/nmap'
        ffufFolder = './output/' + programName + '/ffuf'
        eyewitnessFolder = './output/' + programName + '/eyewitness'
        incrementalDomainsFile = './output/' + programName + '/incrementalDomains.txt'
        incrementalContentFile = './output/' + programName + '/incrementalContent.txt'
        liveHttpDomainsFile = './output/' + programName + '/liveHttpDomains.txt'
        os.makedirs(amassFolder, exist_ok=True, )
        os.makedirs(subfinderFolder, exist_ok=True, )
        os.makedirs(masscanFolder, exist_ok=True, )
        os.makedirs(digFolder, exist_ok=True, )
        os.makedirs(gobusterFolder, exist_ok=True, )
        os.makedirs(nmapFolder, exist_ok=True, )
        os.makedirs(ffufFolder, exist_ok=True, )
        os.makedirs(eyewitnessFolder, exist_ok=True, )
                    
        for target in program['scope']:
            if target['inScope'] == True:
                if 'url' in target:
                    print(target['url'])
                    uniqueURLs.add(target['url'])
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
                    #print(amassArguments)
                    if args.nodomainrecon == None:
                        print("Starting Amass")
                        subprocess.run('amass enum ' + amassArguments, shell=True)
                        print("Done running Amass")

                    #run subfinder
                    subfinderOutputFolder = './output/' + programName + '/subfinder/'
                    if args.nodomainrecon == None:
                        if not os.path.exists(subfinderOutputFolder):
                            os.makedirs(subfinderOutputFolder)
                        print("Starting Subfinder")
                        runSubfinder(programName, domainBase, subfinderOutputFolder)
                        print("Done running Subfinder")

                    #Processing unique names
                    print("Processing domain names for: " + domainBase)
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
                            subfinderOutputFile = subfinderOutputFolder + '/' + filename
                            wildcardDomains = findProbableWildcardDomains(subfinderOutputFile)
                            with open(subfinderOutputFile) as subfinderOut:
                                output = json.load(subfinderOut)
                                for domain in output:    
                                    addDomain = True
                                    try:    
                                        sanitizedDomain = domain.lstrip('.')
                                        for wildcardDomain in wildcardDomains:
                                            wildcardDomainSubdomain = "." + wildcardDomain
                                            if wildcardDomainSubdomain in sanitizedDomain:
                                                addDomain = False
                                                break
                                    except (KeyboardInterrupt, SystemExit):
                                        exit()
                                    except:
                                        print('Error')
                                    if addDomain:
                                        uniqueDomains.add(sanitizedDomain)

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
                        if domain not in oldDataSet and firstRun == False and args.noslack == None:
                            message = 'New domain for ' + programName + ': ' + domain
                            print(message)
                            postToSlack(config["slackWebhookURL"], message)
            
        #add domains to incremental domain list
        with open('./output/' + programName + '/sortedDomains.json', 'r') as current:
            currentData = json.load(current)
            currentDataSet = set(currentData)
            with open(incrementalDomainsFile, 'a+') as inc:
                inc.seek(0)
                incDomains = set(line.strip() for line in inc)
                for domain in currentDataSet:
                    if domain not in incDomains:
                        print('Adding domain ' + domain + ' to incremental list for ' + programName)
                        inc.write("%s\n" % domain)
        with open('./output/' + programName + '/URLs.txt', 'w+') as urls:
                urls.seek(0)
                for url in uniqueURLs:
                    print('Adding url ' + url + ' to url list for ' + programName)
                    urls.write("%s\n" % url)
                        
        print("Done processing domain names")

        #TODO Process massdns output
        #TODO Implement dnsgen
        #cat output/SEEK/incrementalDomains.txt | dnsgen - | ./lib/massdns/bin/massdns -r lib/massdns/lists/resolvers.txt -o J -w output/SEEK/massDnsOutDNSGen.json


        #add domains to incremental content domain list
        contentDomainsFilePath = './output/' + programName + '/contentDomains.json'
        if not os.path.exists(contentDomainsFilePath):
            with open(contentDomainsFilePath, 'w+') as contentDomains:
                print('Created file: ' + contentDomainsFilePath)
        with open(contentDomainsFilePath, 'r') as contentDomains:
            contentDomains.seek(0)
            if contentDomains.read(1):
                contentDomains.seek(0)    
                incrementalContentDomains = json.load(contentDomains)
            else:
                incrementalContentDomains = {}
        addContentDomain('incrementalDomains.txt')
        addContentDomain('URLs.txt')
        
        #Find live domains
        print("Finding live domains")
        if args.nohttprobe == None:
            scriptArguments = masscanIpListFile + ' ' + programName
            subprocess.run('cat ' + incrementalDomainsFile + ' | httprobe > ' + liveHttpDomainsFile, shell=True)
            print("Done running httprobe")

        if args.nomassdns == None:
            massdnsArguments = " -r lib/massdns/lists/resolvers.txt output/" + programName + "/incrementalDomains.txt -o J -w output/" + programName + "/massDnsOutLive.json"
            subprocess.run('./lib/massdns/bin/massdns ' + massdnsArguments, shell=True)

            #Port scan domains. Not done if no massdns
            if args.noportscan == None:
                print("Starting port scan")
                scannedDomains = set([])
                ipList = set([])
                with open('./output/' + programName + '/massDnsOutLive.json', 'r') as dnsRecords:
                    dnsRecords.seek(0)
                    for dnsRecordRow in dnsRecords:
                        dnsRecord = json.loads(dnsRecordRow)
                        if 'resp_type' in dnsRecord:
                            if dnsRecord['resp_type'] == 'A' and dnsRecord['query_name'] == dnsRecord['resp_name']:
                                dnsName = dnsRecord['query_name'].rstrip('.')
                                dnsData = dnsRecord['data'] 
                                if dnsName not in scannedDomains:
                                    scannedDomains.add(dnsName)
                                    ipList.add(dnsData)
                with open(masscanIpListFile, 'w+') as masscanIPList:
                    for ipAddress in ipList:
                        masscanIPList.write("{}\n".format(ipAddress))
                #Running Masscan        
                scriptArguments = masscanIpListFile + ' ' + programName
                subprocess.run('sudo ./masscan.sh ' + scriptArguments, shell=True)
                print("Done running port scan")

                #Summarizing findings
                domainsAndPorts = {}
                domainsAndPortsFiltered = {} 
                if os.path.isdir(masscanFolder):
                    with open(masscanFolder + '/' + programName + '.masscanOut.json', 'r') as masscanOutFile, open('./output/' + programName + '/massDnsOutLive.json', 'r') as dnsRecordsFile :
                        masscanOutFile.seek(0)
                        for row in masscanOutFile:
                            if 'ip' in row:
                                record = json.loads(row.rstrip(',\n'))
                                ipAddress = record['ip'] 
                                dnsRecordsFile.seek(0)
                                for dnsRecordRow in dnsRecordsFile:
                                    dnsRecord = json.loads(dnsRecordRow)
                                    if 'resp_type' in dnsRecord:
                                        if dnsRecord['resp_type'] == 'A' and dnsRecord['query_name'] == dnsRecord['resp_name']:
                                            dnsName = dnsRecord['query_name'].rstrip('.')
                                            dnsIp = dnsRecord['data'] 
                                            if ipAddress == dnsIp:
                                                if dnsRecord['resp_name'] in domainsAndPorts:
                                                    domainsAndPorts[dnsRecord['resp_name']]['ipAdresses'].append({ipAddress: record['ports']})
                                                else:    
                                                    domainsAndPorts[dnsRecord['resp_name']] = {'ipAdresses':[{ipAddress: record['ports']}]}
                                                for port in record['ports']:
                                                    if port['port'] not in [80, 443]:
                                                        if dnsRecord['resp_name'] in domainsAndPortsFiltered:
                                                            domainsAndPortsFiltered[dnsRecord['resp_name']]['ipAdresses'].append({ipAddress: record['ports']})
                                                            break
                                                        else:    
                                                            domainsAndPortsFiltered[dnsRecord['resp_name']] = {'ipAdresses':[{ipAddress: record['ports']}]}
                                                            break
                                dnsRecordsFile.seek(0)
                    with open('./output/' + programName + '/domainsAndPorts.json', 'w+') as f:
                            json.dump(domainsAndPorts, f)
                    with open('./output/' + programName + '/domainsAndPortsFiltered.json', 'w+') as f:
                            json.dump(domainsAndPortsFiltered, f)
            if args.nobanner == None:
                #Banner Grabbing
                print('Starting banner grabbing')
                filteredDomainsFilePath = './output/' + programName + '/domainsAndPortsFiltered.json'
                if os.path.exists(filteredDomainsFilePath): 
                    with open(filteredDomainsFilePath, 'r+') as filteredDomainsFile:
                        filteredDomainsFile.seek(0)
                        filteredDomains = json.load(filteredDomainsFile)
                        for filteredDomain in filteredDomains:
                            for ipAdresses in filteredDomains[filteredDomain]['ipAdresses']:
                                for ipAdress in ipAdresses:
                                    scriptArguments = str(ipAdresses[ipAdress][0]['port']) + " " + filteredDomain.rstrip('.') + " " + programName
                                    print(scriptArguments)
                                    subprocess.run('sudo ./nmapBannerGrab.sh ' + scriptArguments, shell=True)
                print('Done banner grabbing')       
        #Find URLs from wayback machine
        if args.nowayback == None:
            print("Starting Wayback Machine discovery")

            subprocess.run('cat output/' + programName + '/incrementalDomains.txt | waybackurls > output/' + programName + '/waybackurlsOut.txt', shell=True)
            subprocess.run('cat output/' + programName + '/URLs.txt | waybackurls >> output/' + programName + '/waybackurlsOut.txt', shell=True)
            #cleaning output
            subprocess.run("sed -i '/^$/d'  output/" + programName + "/waybackurlsOut.txt", shell=True)
            print("Done running Wayback Machine discovery")
        #Content discovery
        if args.nocontent == None:
            with open('./output/' + programName + '/contentDomains.json', 'r') as domains:
                domains.seek(0)
                contentDomains = json.load(domains)
                print("Starting content discovery with ffuf")
                for domain in contentDomains:
                    if args.nohttp == None and args.nocontent == None:
                        urlHttp = "http://" + domain
                        #TODO
                        #subprocess.run('ffuf ' + scriptArguments, shell=True)
                    
                    if 'Status' in contentDomains[domain]:
                        if contentDomains[domain]['Status'] == 'Enabled':
                            urlHttps = "https://" + domain
                            outfileHttps = ffufFolder + '/https@' + domain + '.json'
                            outfileHttpsIncremental = ffufFolder + '/https@' + domain + '.incremental.txt'
                            scriptArguments = ' -t 100 -timeout 3 -r -w '
                            if 'ContentScanLevel' in contentDomains[domain]:
                                if contentDomains[domain]['ContentScanLevel'] == 'Full':
                                    scriptArguments += 'wordlists/directories/content_discovery_nullenc0de.txt '
                            else:
                                    scriptArguments += 'lib/SecLists/Discovery/Web-Content/SVNDigger/all.txt '
                            scriptArguments += '-u ' + urlHttps + '/FUZZ -o ' + outfileHttps + ' -ac '
                            if 'FilterSize' in contentDomains[domain]:
                                scriptArguments += ' -fs ' + contentDomains[domain]['FilterSize']
                            if 'RequestDelay' in contentDomains[domain]:
                                scriptArguments += ' -p ' + contentDomains[domain]['RequestDelay']
                            if 'FilterWords' in contentDomains[domain]:
                                scriptArguments += ' -fw ' + contentDomains[domain]['FilterWords']
                            print(scriptArguments)
                            try:
                                subprocess.run('~/go/bin/ffuf ' + scriptArguments, shell=True)
                            except:
                                pass

                            #add https content to incremental content list
                            addedContent = False
                            try:
                                with open(outfileHttps, 'r') as current:
                                    currentData = json.load(current)
                                    with open(outfileHttpsIncremental, 'a+') as inc:
                                        inc.seek(0)
                                        incContent = set(line.strip() for line in inc)
                                        if 'results' in currentData:
                                            for content in currentData['results']:
                                                contentURL = urlHttps + '/' + content['input']
                                                if contentURL not in incContent:
                                                    print('Adding ' + contentURL + ' to incremental list for ' + urlHttps)
                                                    inc.write("%s\n" % contentURL)
                                                    addedDomains = True
                                if addedContent and args.noslack == None:
                                    message = 'New content for ' + programName + ' domain: ' + domain
                                    print(message)
                                    postToSlack(config["slackWebhookURL"], message)
                            except:
                                pass
                print("Done running ffuf")
        #Incrementing content
        scriptArguments = ffufFolder + ' ' + outputFolder
        subprocess.run('./incrementContent.sh ' + scriptArguments, shell=True)
        if args.definedcontentonly == None:
            subprocess.run('cat ' + liveHttpDomainsFile + ' >> ' + incrementalContentFile, shell=True)

        if args.noeyewitness == None:
            scriptArguments = programName
            subprocess.run('./eyeWitnessCapture.sh ' + scriptArguments, shell=True)
