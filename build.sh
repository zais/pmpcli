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
