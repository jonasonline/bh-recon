#input program name ($1), input file name ($2), output directory name ($3)
cp ${PWD}/output/$1/$2 ${PWD}/output/$1/eyewitness/$3
docker run --rm -it -v ${PWD}/output/$1/eyewitness/$3:/tmp/EyeWitness eyewitness --web -f /tmp/EyeWitness/$2 --timeout 20 --prepend-https