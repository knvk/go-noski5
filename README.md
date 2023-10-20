# go-noski5
Socks5 implementation attempt in native GO

## build

```
go build ./
```

## run 

```
./go-noski5 users.txt
```

`users.txt` must contain user:pass one per line

## test

```
curl --socks5 localhost:8000 http://example.org
curl --socks5-hostname localhost:8000 http://example.org
curl -x "socks5://user:pass@127.0.0.1:8000" http://example.org
```

## limitations 
- no rulesets
- only connect method