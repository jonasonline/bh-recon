#find ./output/$1 -name \*.incremental.txt -exec cat {} > output/$1/eyewitness/allContentIncremental.txt \;
#input program name
cp ${PWD}/output/$1/incrementalContent.txt ${PWD}/output/$1/eyewitness/
docker run --rm -it -v ${PWD}/output/$1/eyewitness:/tmp/EyeWitness eyewitness --web -f /tmp/EyeWitness/incrementalContent.txt --timeout 20 --prepend-https