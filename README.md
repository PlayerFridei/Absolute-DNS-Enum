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

By downloading and using this tool, you agree to the following terms:

1. The tool is provided without any warranty, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.

2. The creator of the tool shall not be liable for any direct, indirect, incidental, special, consequential, or exemplary damages, including but not limited to, damages for loss of profits, goodwill, use, data, or other intangible losses.

3. You understand and acknowledge that the tool is still under development and may not be fully polished. As such, it might contain bugs or other issues that could affect its performance.

4. You understand and acknowledge that the creator of the tool may, at their sole discretion, discontinue support for the tool at any time and without notice. This means that there is no guarantee of ongoing maintenance, updates, or technical assistance.

5. You agree to use the tool at your own risk and understand that the creator of the tool does not provide any assurances regarding its functionality, reliability, or suitability for any purpose.

6. The creator of the tool reserves the right to modify, suspend, or terminate the tool at any time, with or without cause, and without liability to you or any third party.

By downloading and using the tool, you acknowledge that you have read, understood, and agreed to these terms. If you do not agree with any part of these terms, you should not download or use the tool.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.