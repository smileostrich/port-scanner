# port-scanner
port, dns scanner

### usage
```bash
port-scanner --target google.com --concurrency 16 --subdomains-file sub-domains.txt
```

### status
- [x] dns scanner
- [ ] port scanner

### expected output
```json
{"name":"google.com","addresses":[{"ip":"~~~"}],"subdomains":[{"name":"sub1.google.com","addresses":[{"ip":"~~~"}]},{"name":"sub2.google.com","addresses":[{"ip":"~~~"}]}]}
```
