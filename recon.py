import json

with open('programs.json') as programsFile:
    programs = json.load(programsFile)
    
    for program in programs['programs']:
        print(program)

with open('amass_output/amass_data.json') as amassOut:
    output = json.load(amassOut)
    print(output)
    
