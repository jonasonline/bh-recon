#input file ($1), output directory ($2)
#Disabled docker as current ew image is buggy
#cp ${PWD}/output/$1/$2 ${PWD}/output/$1/eyewitness/$3
#docker run --rm -it -v ${PWD}/output/$1/eyewitness/$3:/tmp/EyeWitness eyewitness --web -f /tmp/EyeWitness/$2 --timeout 20 --prepend-https
./lib/EyeWitness/Python/EyeWitness.py -f $1 -d $2 --timeout 20 --no-prompt