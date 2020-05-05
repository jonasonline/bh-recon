import json, os, subprocess, shutil, requests, argparse, socket, urllib3, datetime, pydig, sys
from multiprocessing import Pool
from tld import get_tld


now = datetime.datetime.now()
dateString = now.strftime("%Y%m%d")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
parser.add_argument('--nosubdomaintakeover', action='store_const', const=True, help="Skip subdomain takeover check")
parser.add_argument('--nourlstatus', action='store_const', const=True, help="Skip URL status check")
parser.add_argument('--noeyewitness', action='store_const', const=True, help="Skip screen capture with EyeWitness")
parser.add_argument('--nocontentscreenshots', action='store_const', const=True, help="Skip screen capture of content with EyeWitness")
parser.add_argument('--nodomainrootscreenshots', action='store_const', const=True, help="Skip screen capture of content with EyeWitness")

args = parser.parse_args()

def postToSlack(webhookURL, message):
    requests.post(webhookURL, json={"text":message})
def myconverter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()
def runSubfinder(programName, domainsFilePath, outputFile):
    subfinderArguments = ' -dL ' + domainsFilePath + ' -nW -t 100 -silent > ' + outputFile
    #print(subfinderArguments)
    subprocess.run('~/go/bin/subfinder ' + subfinderArguments, shell=True)

def testForWildcardDomains(domainSet):
    wildcardDomains = set([])
    for domain in domainSet:
        try:
            topLevelDomain = get_tld("https://" + domain, fail_silently=True, as_object=True)
            baseDomain = topLevelDomain.fld
            topLevelDomain = topLevelDomain.tld
            subDomains = domain.split("." + baseDomain)
            if len(subDomains) <= 1:
                continue 
            subDomains = subDomains[0]
            subDomains = subDomains.split(".")
            referenceResponse = set(pydig.query(domain, 'A'))
            if len(referenceResponse) >= 1:
                for subDomain in subDomains:
                    try:
                        probeDomain = '*.' + domain
                        probeDomain = probeDomain.replace('*.' + subDomain + '.', '*.', 1)
                        probeResponse = set(pydig.query(probeDomain, 'A'))
                        if len(probeResponse) >= 1:
                            if (len(referenceResponse - probeResponse) + len(probeResponse - referenceResponse)) == 0:
                                wildcardDomains.add(domain)
                                continue
                    except Exception as e:
                        print('Error in wildcard domain check: ' + str(e))
                        pass
                    
        except Exception as e:
            print('Error in wildcard domain check: ' + str(e))
    return wildcardDomains


def addContentDomain(inputURLTextFileName, incrementalContentDomains, programName):
    with open('./output/' + programName + '/' + inputURLTextFileName, 'r') as inputFile:
            inputFile.seek(0)
            incDomains = set(line.strip() for line in inputFile)
            for domain in incDomains:
                if domain not in incrementalContentDomains:
                    incrementalContentDomains[domain] = {"Added": datetime.datetime.now(), "Status": "Pending"}
            with open('./output/' + programName + '/contentDomains.json', 'w') as contentDomains:
                json.dump(incrementalContentDomains, contentDomains, default = myconverter)

def probeURL(url):
    status = {}
    status['url'] = url
    try:
        response = requests.get(url, timeout=2)
    except requests.exceptions.SSLError as e:
        status['SSLError'] = str(e)
        try:
            response = requests.get(url, verify=False, timeout=2)
        except requests.exceptions.RequestException as e:
                print(e)
                return status
    except requests.exceptions.ConnectTimeout:
        status['timedOut'] = 1
        return status

    except requests.exceptions.RequestException as e:
        status['connectionError'] = 1
        return status
    status['statusCode'] = response.status_code
    status['text'] = response.text
    status['history'] = str(response.history)
    status['headers'] = str(response.headers)
    if 'content-length' in response.headers:
        status['contentLength'] = response.headers['content-length']
    if 'ETag' in response.headers:
        status['ETag'] = str(response.headers['ETag'])

    return status

def statusForUrls(urlsTextFile, outputFile):
    statusForUrls = {}
    if not os.path.exists(outputFile):
                with open(outputFile, 'w+'):
                    print('Created file: ' + outputFile)

    with open(outputFile, 'r') as read_file:
        read_file.seek(0)
        if read_file.read(1):
            read_file.seek(0)
            statusForUrls = json.load(read_file)

    with open(urlsTextFile, 'r') as urlList:
        urls = urlList.readlines()
        for url in urls:
            strippedUrl = url.strip()
            status = probeURL(strippedUrl)
            if strippedUrl in statusForUrls:
                if 'statusCode' in status and 'statusCode' in statusForUrls[strippedUrl]:
                    if statusForUrls[strippedUrl]['statusCode'] != status['statusCode']:
                        if args.noslack == None:
                            message = 'Status code changed from ' + str(statusForUrls[strippedUrl]['statusCode']) + ' to ' + str(status['statusCode']) + ' for: ' + statusForUrls[strippedUrl]['url']
                            print(message)
                            postToSlack(config["slackWebhookURL"], message)
                if 'ETag' in status and 'ETag' in statusForUrls[strippedUrl]:
                    if statusForUrls[strippedUrl]['ETag'] != status['ETag']:
                        print('ETag changed from ' + str(statusForUrls[strippedUrl]['ETag']) + ' to ' + str(status['ETag']) + ' for: ' + statusForUrls[strippedUrl]['url'])
                if 'contentLength' in status and 'contentLength' in statusForUrls[strippedUrl]:
                    if statusForUrls[strippedUrl]['contentLength'] != status['contentLength']:
                        if args.noslack == None:
                            message = 'Content length changed from ' + str(statusForUrls[strippedUrl]['contentLength']) + ' to ' + str(status['contentLength']) + ' for: ' + statusForUrls[strippedUrl]['url']
                            print(message)
                            postToSlack(config["slackWebhookURL"], message)
            statusForUrls[status['url']] = status
        with open(outputFile, 'w') as outFile:
            outFile.write(json.dumps(statusForUrls, indent=4))

def okUrlsToFile(inputJsonFile, outputTextFile):
    if not os.path.exists(outputTextFile):
            with open(outputTextFile, 'w+'):
                print('Created file: ' + outputTextFile)
    if os.path.exists(inputJsonFile):
        outputUrls = set([])
        with open(inputJsonFile, 'r') as read_file:
            print('Reading URLs from file: ' + inputJsonFile)
            read_file.seek(0)
            if read_file.read(1):
                read_file.seek(0)
                urls = json.load(read_file)
                for url in urls:
                    print('Checking URL: ' + url)
                    if 'url' in urls[url] and 'statusCode' in urls[url]:
                        if urls[url]['statusCode'] == 200:
                            urlToAdd = urls[url]['url']
                            outputUrls.add(urlToAdd + "\n")
        with open(outputTextFile, 'w') as outFile:
            outFile.writelines(outputUrls)

def processProgram(program):
        if program['enabled'] == False:
            return
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
        subdomainTakeoverFolder = './output/' + programName + '/subdomainTakeover'
        ffufFolder = './output/' + programName + '/ffuf'
        eyewitnessFolder = './output/' + programName + '/eyewitness'
        contentScreenShotsFolder = eyewitnessFolder + '/content'
        domainRootScreenShotsFolder = eyewitnessFolder + '/domainRoot'
        incrementalDomainsFile = './output/' + programName + '/incrementalDomains.txt'
        incrementalContentFile = './output/' + programName + '/incrementalContent.txt'
        statusForContentUrlsFile = './output/' + programName + '/statusForContentUrls.txt'
        liveHttpDomainsFile = './output/' + programName + '/liveHttpDomains.txt'
        statusForLiveHttpDomainsFile = './output/' + programName + '/statusForLiveHttpDomains.txt'
        okIncrementalContentFile = './output/' + programName + '/okIncrementalContent.txt'
        okliveHttpDomainsFile = './output/' + programName + '/okLiveHttpDomains.txt'
        excludeDomainsFile = './output/' + programName + '/excludeDomainNames.json'
        massDnsInputFile = './output/' + programName + '/massDnsInputDomainNames.txt'
        os.makedirs(amassFolder, exist_ok=True, )
        os.makedirs(subfinderFolder, exist_ok=True, )
        os.makedirs(masscanFolder, exist_ok=True, )
        os.makedirs(digFolder, exist_ok=True, )
        os.makedirs(gobusterFolder, exist_ok=True, )
        os.makedirs(nmapFolder, exist_ok=True, )
        os.makedirs(subdomainTakeoverFolder, exist_ok=True, )
        os.makedirs(ffufFolder, exist_ok=True, )
        os.makedirs(eyewitnessFolder, exist_ok=True, )
        os.makedirs(contentScreenShotsFolder, exist_ok=True, )
        os.makedirs(domainRootScreenShotsFolder, exist_ok=True, )

        if args.program != None and args.program != program['programName']:
            return
        wildcardDomains = set([])
        rootDomainsInScope = set([])            
        for target in program['scope']:
            if target['inScope'] == True:
                if 'url' in target:
                    print('Adding URL: ' + target['url'])
                    uniqueURLs.add(target['url'])
                elif 'domain' in target:
                    domainBase = target['domain'].replace('*.','')
                    print('Adding domain: ' + domainBase)
                    rootDomainsInScope.add(domainBase)

        with open('./output/' + programName + '/rootDomainsInScope.txt', 'w') as rootDomainsInScopeFile:
            for index, rootDomain in enumerate(rootDomainsInScope):
                if index + 1 < len(rootDomainsInScope):
                    rootDomainsInScopeFile.write("%s\n" % rootDomain)
                else:
                    rootDomainsInScopeFile.write("%s" % rootDomain)
        #run amass
        amassArguments = ' -df ./output/' + programName + '/rootDomainsInScope.txt -dir ./output/' + programName + '/amass/ --json ./output/LINE/amass/amass_' + programName + ' .json -r 9.9.9.9, 8.8.8.8, 1.1.1.1'
        if args.nodomainrecon == None:
            print("Starting Amass for program: " + programName)
            #print(amassArguments)
            subprocess.run('amass enum ' + amassArguments, shell=True)
            print("Done running Amass for program: " + programName)
        
        #run subfinder
        subfinderOutputFolder = './output/' + programName + '/subfinder/'
        if args.nodomainrecon == None:
            if not os.path.exists(subfinderOutputFolder):
                os.makedirs(subfinderOutputFolder)
            print("Starting Subfinder")
            runSubfinder(programName, './output/' + programName + '/rootDomainsInScope.txt', subfinderOutputFolder + 'subfinder_out.txt')
            print("Done running Subfinder")

        #Processing amass unique names
        print("Processing domain names for: " + programName)
        #Amass unique names
        with open(amassFolder + '/amass_' + programName + '.json') as amassOut:
            for line in amassOut:
                try:    
                    output = json.loads(line)
                    uniqueDomains.add(output['name'])
                except:
                    print('Error')
                
        #Subfinder unique names
        for filename in os.listdir(subfinderOutputFolder):
            if filename.endswith('.json'):
                subfinderOutputFile = subfinderOutputFolder + 'subfinder_out.txt'
                #Parsing Subfinder output for wildcard domains.
                with open(subfinderOutputFile) as subOut:
                    subOut.seek(0)
                    for domain in subOut:    
                        uniqueDomains.add(domain)                                    
                        
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
                for index, domain in enumerate(currentDataSet):
                    if domain not in incDomains:
                        print('Adding domain ' + domain + ' to incremental list for ' + programName)
                        if index + 1 < len(incDomains):
                            inc.write("%s\n" % domain)
                        else:
                            inc.write("%s" % domain)
        with open('./output/' + programName + '/URLs.txt', 'w+') as urls:
                urls.seek(0)
                for index, url in enumerate(uniqueURLs):
                    print('Adding url ' + url + ' to url list for ' + programName)
                    if index + 1 < len(uniqueURLs): 
                        urls.write("%s\n" % url)
                    else:
                        urls.write("%s" % url)
                        
        print("Done processing domain names for program: " + programName)
        
        #TODO Implement dnsgen and massdns in combo
        #cat output/SEEK/incrementalDomains.txt | dnsgen - | ./lib/massdns/bin/massdns -r lib/massdns/lists/resolvers.txt -o J -w output/SEEK/massDnsOutDNSGen.json
        
        #Add domains to incremental content domain list
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
        addContentDomain('incrementalDomains.txt', incrementalContentDomains, programName)
        addContentDomain('URLs.txt', incrementalContentDomains, programName)
        
        #Run massdns
        if args.nomassdns == None or args.nodomainrecon == True:
            with open(incrementalDomainsFile, 'r') as incrementalDomains:
                incrementalDomains.seek(0)
                domainNameList = set([])
                if os.path.exists(excludeDomainsFile):
                    with open(excludeDomainsFile, 'r') as excludeDomainNamesFile:
                        excludeDomainNamesFile.seek(0)
                        excludeDomains = json.load(excludeDomainNamesFile)
                        for domainName in incrementalDomains:
                            domainNameList.add(domainName)
                            if domainName in excludeDomains:
                                if 'massdns' in excludeDomains[domainName]:
                                    domainNameList.remove(domainName)
                    with open(massDnsInputFile, 'w+') as massDnsInputDomainNames:
                        for domainName in domainNameList:
                            massDnsInputDomainNames.write("{}".format(domainName))
                else:
                    shutil.copyfile(incrementalDomainsFile, massDnsInputFile)


            massdnsArguments = " -q -r lib/massdns/lists/resolvers.txt output/" + programName + "/incrementalDomains.txt -o J -w output/" + programName + "/massDnsOut.json"
            subprocess.run('./lib/massdns/bin/massdns ' + massdnsArguments, shell=True)

            #Port scan domains. Not done if no massdns
            if args.noportscan == None:
                print("Starting port scan")
                scannedDomains = set([])
                ipList = set([])
                with open('./output/' + programName + '/massDnsOut.json', 'r') as dnsRecords:
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
                    with open(masscanFolder + '/' + programName + '.masscanOut.json', 'r') as masscanOutFile, open('./output/' + programName + '/massDnsOut.json', 'r') as dnsRecordsFile :
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


        #TODO improve wildcard domain logging
        if os.path.isfile('./output/' + programName + '/wildcardDomains.txt') and len(wildcardDomains) > 0:
            with open('./output/' + programName + '/wildcardDomains.txt', 'w') as wildcardDomainsFile:
                for index, wildcardDomain in enumerate(wildcardDomains):
                    if index + 1 < len(wildcardDomains):
                        wildcardDomainsFile.write("%s\n" % wildcardDomain)
                    else:
                        wildcardDomainsFile.write("%s" % wildcardDomain)
        
        #TODO Do not check wildcard domains
        #Find live domains
        if args.nohttprobe == None:
            print("Finding live domains with httprobe")
            print('cat ' + incrementalDomainsFile + ' | httprobe > ' + liveHttpDomainsFile)
            subprocess.run('cat ' + incrementalDomainsFile + ' | httprobe > ' + liveHttpDomainsFile, shell=True)
            print("Done running httprobe")        

        #Find URLs from wayback machine
        if args.nowayback == None:
            print("Starting Wayback Machine discovery")

            subprocess.run('cat output/' + programName + '/incrementalDomains.txt | sort | uniq | waybackurls > output/' + programName + '/waybackurlsOut.txt', shell=True)
            subprocess.run('cat output/' + programName + '/URLs.txt | sort | uniq | waybackurls >> output/' + programName + '/waybackurlsOut.txt', shell=True)
            #cleaning output
            subprocess.run("sed -i '/^$/d'  output/" + programName + "/waybackurlsOut.txt", shell=True)
            print("Done running Wayback Machine discovery")

        #Checking subdomain takeover
        if args.nosubdomaintakeover == None:
            print('Starting subdomain takeover check')
            scriptArguments = '-w ' + incrementalDomainsFile + ' -c lib/subjack/fingerprints.json -t 100 -timeout 30 -ssl -o ' + subdomainTakeoverFolder + '/takeoverOutput.txt'
            subprocess.run('subjack ' + scriptArguments, shell=True)            
            print('Done running subdomain takeover check')

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
                                                    addedContent = True
                                if addedContent and args.noslack == None:
                                    message = 'New content for ' + programName + ' domain: ' + domain
                                    print(message)
                                    postToSlack(config["slackWebhookURL"], message)
                            except:
                                pass
            print("Done running ffuf")
            #Incrementing content
            if os.listdir(ffufFolder):
                scriptArguments = ffufFolder + ' ' + outputFolder
                subprocess.run('./incrementContent.sh ' + scriptArguments, shell=True)

        #Checking and logging status for URLs
        if args.nourlstatus == None:
            if os.path.exists(incrementalContentFile):
                statusForUrls(incrementalContentFile, statusForContentUrlsFile)
                okUrlsToFile(statusForContentUrlsFile, okIncrementalContentFile)
                
            if os.path.exists(incrementalContentFile):    
                statusForUrls(liveHttpDomainsFile, statusForLiveHttpDomainsFile)
                okUrlsToFile(statusForLiveHttpDomainsFile, okliveHttpDomainsFile)

        #Capturing screenshots
        if args.noeyewitness == None:
            #TODO input program name ($1), input file name ($2), output directory name ($3)
            if args.nocontentscreenshots == None and os.path.exists(okIncrementalContentFile):
                scriptArguments = okIncrementalContentFile + '  ./output/' + programName + '/eyewitness/content/' + dateString 
                print(scriptArguments)
                subprocess.run('./eyeWitnessCapture.sh ' + scriptArguments, shell=True)
            if args.nodomainrootscreenshots == None and os.path.exists(okliveHttpDomainsFile):
                scriptArguments = okliveHttpDomainsFile + '  ./output/' + programName + '/eyewitness/domainRoot/' + dateString
                print(scriptArguments)
                subprocess.run('./eyeWitnessCapture.sh ' + scriptArguments, shell=True)



with open('config.json', 'r') as configFile:
    config = json.load(configFile)

with open('programs.json') as programsFile:
    programs = json.load(programsFile)
    with Pool(processes=4) as pool:
        pool.map(processProgram, programs['programs'])   

