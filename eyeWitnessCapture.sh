find ./output/$1 -name \*.incremental.txt -exec cat {} > output/$1/eyewitness/allContentIncremental.txt \;
docker build --build-arg user=$USER --tag eyewitness lib/EyeWitness
docker run --rm -it -v ${PWD}/output/$1/eyewitness:/tmp/EyeWitness eyewitness --web -f /tmp/EyeWitness/allContentIncremental.txt
