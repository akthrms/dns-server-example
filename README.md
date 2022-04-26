# DNS Server Sample

[Building a DNS Server in Rust](https://github.com/EmilHernvall/dnsguide)

```
$ cargo run
DnsHeader {
    id: 64379,
    recursion_desired: true,
    truncated_message: false,
    authoritative_answer: false,
    operation_code: 0,
    response: true,
    result_code: NOERROR,
    checking_disabled: false,
    authenticated_data: false,
    z: false,
    recursion_available: true,
    questions: 1,
    answers: 1,
    authoritative_entries: 0,
    resource_entries: 0,
}
DnsQuestion {
    name: "google.com",
    query_type: A,
}
A {
    domain: "google.com",
    address: 172.217.161.206,
    ttl: 94,
}
```
