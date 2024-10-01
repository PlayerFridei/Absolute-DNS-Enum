# Advanced DNS Enumeration Tool

This is an advanced DNS enumeration tool designed to comprehensively query and retrieve all possible DNS records associated with a domain. It offers two scanning modes: a quick "Normal Scan" for common DNS records and an "Absolute Scan" that covers all possible DNS record types, including obscure and deprecated records.

## Features

- **Comprehensive DNS Record Enumeration**: Retrieves standard, security-related, and even rare DNS records.
- **Customizable Scan Modes**:
  - **Normal Scan**: Queries the most commonly used DNS records (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`).
  - **Absolute Scan**: Queries all possible DNS records, including `A`, `NS`, `MD`, `MF`, `CNAME`, `SOA`, `MB`, `MG`, `MR`, `NULL`, `WKS`, `PTR`, `HINFO`, `MINFO`, `MX`, `TXT`, `RP`, `AFSDB`, `X25`, `ISDN`, `RT`, `NSAP`, `NSAP-PTR`, `SIG`, `KEY`, `PX`, `GPOS`, `AAAA`, `LOC`, `NXT`, `SRV`, `NAPTR`, `KX`, `CERT`, `A6`, `DNAME`, `OPT`, `APL`, `DS`, `SSHFP`, `IPSECKEY`, `RRSIG`, `NSEC`, `DNSKEY`, `DHCID`, `NSEC3`, `NSEC3PARAM`, `TLSA`, `SMIMEA`, `HIP`, `NINFO`, `CDS`, `CDNSKEY`, `OPENPGPKEY`, `CSYNC`, `ZONEMD`, `SVCB`, `HTTPS`, `SPF`, `UNSPEC`, `NID`, `L32`, `L64`, `LP`, `EUI48`, `EUI64`, `TKEY`, `TSIG`, `IXFR`, `AXFR`, `MAILB`, `MAILA`, `ANY`, `URI`, `CAA`, `AVC`, `AMTRELAY`, `TA`, and `DLV`.

- **Formatted Output**: Presents DNS records in a clear and readable format, with explanations for each record type.
- **Error Handling**: Robust error handling for common DNS issues such as timeouts, non-existent domains, and invalid record types.

## Installation

First, clone the repository:

```sh
git clone https://github.com/PlayerFridei/Absolute-DNS-Enum
```

```sh
cd Absolute-DNS-Enum
```

```sh
pip install -r requirements.txt
```

```sh
python DNSenum.py
```

# Disclaimer

> Before using this software, you agree to the terms outlined in our [SECURITY.md](SECURITY.md) policy.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.