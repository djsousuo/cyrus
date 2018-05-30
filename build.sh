#!/bin/bash

GO=/Users/nima/Documents/Projects/go/bin/go

rm -rf build/
mkdir -p build/addons

# Build Project
${GO} build -o build/proxy ./proxy/
cp ./proxy/config.yml build/

# Build Project
${GO} build -o build/worker ./worker/

# Build Modules
for f in $(find worker/modules -name \*.go)
do
    dir=$(dirname ${f})
    module=$(basename ${dir})
    ${GO} build -buildmode=plugin -o build/addons/${module}.so ${f}
    cp ${dir}/${module}.yml build/addons/${module}.yml 2>/dev/null
    cp ${dir}/${module}.txt build/addons/${module}.txt 2>/dev/null
done

#docker run -d -p 5672:5672 rabbitmq
#docker run -d -p 6379:6379 redis
#docker run -d -p 5050:5050 nim4/browser
#docker run -d -p 80:80 feltsecure/owasp-bwapp

# Run proxy
./build/proxy -config ./build/config.yml
