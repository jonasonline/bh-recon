#find ./output/$1 -name \*.incremental.txt -exec cat {} > output/$1/eyewitness/allContentIncremental.txt \;
cp ${PWD}/output/$1/incrementalContent.txt ${PWD}/output/$1/eyewitness/
docker build --build-arg user=$USER --tag eyewitness lib/EyeWitness
docker run --rm -it -v ${PWD}/output/$1/eyewitness:/tmp/EyeWitness eyewitness --web -f /tmp/EyeWitness/incrementalContent.txt --timeout 20 --prepend-https