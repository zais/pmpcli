#!/bin/sh
# exit on failed commands
set -e

# update build number
sed -i -re 's/const BUILD = .+/const BUILD ="'$(date +%Y%m%d%H%M)'"/g' pmpcli.go

# install local bin
go install

# build binaries
for os in linux darwin windows
do
  if [ $os = "windows" ]; then
    ext=".exe"
  else
    ext=""
  fi
  for arch in 386 amd64
  do
    GOOS=$os GOARCH=$arch go build -o bin/pmpcli_${os}_${arch}${ext} -v github.com/zais/pmpcli
  done
done

echo DONE
