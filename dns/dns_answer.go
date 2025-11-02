package dns

type DNSAnswer struct  {
    Name     string
    Type     uint16
    Class    uint16
    TTL      uint32
    RDLength uint16
    RData    []byte
}