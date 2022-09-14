# go-noski5
Socks5 implementation attempt in native GO

## build

```
go build -o noski5 main.go
```

## run 

```
./noski5
```

## test

```
curl --socks5 localhost:8000 http://example.org
```

## limitations 
- no rulesets
- only connect method
- only noauth method
