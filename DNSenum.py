import dns.resolver

class DNSEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        # Record types for Normal and Absolute scans
        self.normal_record_types = [
            'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'
        ]
        self.absolute_record_types = [
            'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV', 'CAA',
            'NAPTR', 'LOC', 'HINFO', 'RP', 'TLSA', 'SSHFP', 'SPF', 'URI',
            'DNSKEY', 'RRSIG', 'DS', 'NSEC', 'NSEC3', 'HIP', 'DNAME', 'CDS',
            'CDNSKEY', 'OPENPGPKEY', 'TKEY', 'TSIG', 'APL', 'AFSDB', 'X25', 
            'ISDN', 'RT', 'NSAP', 'SMIMEA', 'IPSECKEY', 'TALINK', 'NINFO', 'RKEY'
        ]

        # Mapping record types to their respective formatting functions
        self.formatting_functions = {
            'A': self.format_a_record,
            'AAAA': self.format_aaaa_record,
            'CNAME': self.format_cname_record,
            'MX': self.format_mx_record,
            'NS': self.format_ns_record,
            'TXT': self.format_txt_record,
            'SOA': self.format_soa_record,
            'PTR': self.format_ptr_record,
            'SRV': self.format_srv_record,
            'CAA': self.format_caa_record,
            'NAPTR': self.format_naptr_record,
            'LOC': self.format_loc_record,
            'HINFO': self.format_hinfo_record,
            'RP': self.format_rp_record,
            'TLSA': self.format_tlsa_record,
            'SSHFP': self.format_sshfp_record,
            'SPF': self.format_spf_record,
            'URI': self.format_uri_record,
            'DNSKEY': self.format_dnskey_record,
            'RRSIG': self.format_rrsig_record,
            'DS': self.format_ds_record,
            'NSEC': self.format_nsec_record,
            'NSEC3': self.format_nsec3_record,
            'HIP': self.format_hip_record,
            'DNAME': self.format_dname_record,
            'CDS': self.format_cds_record,
            'CDNSKEY': self.format_cdnskey_record,
            'OPENPGPKEY': self.format_openpgpkey_record,
            'TKEY': self.format_tkey_record,
            'TSIG': self.format_tsig_record,
            'APL': self.format_apl_record,
            'AFSDB': self.format_afsdb_record,
            'X25': self.format_x25_record,
            'ISDN': self.format_isdn_record,
            'RT': self.format_rt_record,
            'NSAP': self.format_nsap_record,
            'SMIMEA': self.format_smimea_record,
            'IPSECKEY': self.format_ipseckey_record,
            'TALINK': self.format_talink_record,
            'NINFO': self.format_ninfo_record,
            'RKEY': self.format_rkey_record
        }

    def query_record(self, record_type):
        """Query a specific DNS record type for the domain."""
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            return [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            return [f"No {record_type} record found."]
        except dns.resolver.NXDOMAIN:
            return ["Domain does not exist."]
        except dns.resolver.NoNameservers:
            return ["No name servers responded."]
        except dns.resolver.Timeout:
            return ["Query timed out."]
        except dns.exception.SyntaxError:
            return ["Invalid record type."]
        except Exception as e:
            return [str(e)]

    def format_record(self, record_type, records):
        """Format DNS record using the appropriate function."""
        formatter = self.formatting_functions.get(record_type, self.format_default_record)
        return formatter(records)

    def format_default_record(self, records):
        """Default formatting for unknown record types."""
        return [f"Record: {record}" for record in records]

    def format_a_record(self, records):
        return [f"IPv4 Address: {record}" for record in records]

    def format_aaaa_record(self, records):
        return [f"IPv6 Address: {record}" for record in records]

    def format_cname_record(self, records):
        return [f"Canonical Name (Alias): {record}" for record in records]

    def format_mx_record(self, records):
        return [f"Mail Server: {record.split()[1]} (Priority: {record.split()[0]})" for record in records]

    def format_ns_record(self, records):
        return [f"Name Server: {record}" for record in records]

    def format_txt_record(self, records):
        return [f"Text Record: {record}" for record in records]

    def format_soa_record(self, records):
        """Format SOA record for better readability."""
        formatted_records = []
        for soa_record in records:
            parts = soa_record.split()
            formatted_records.append(
                f"Primary Name Server: {parts[0]}\n"
                f"Responsible Authority's Email: {parts[1].replace('.', '@', 1)}\n"
                f"Serial Number: {parts[2]} (Used for zone versioning)\n"
                f"Refresh Interval: {parts[3]} seconds (Time before the zone should be refreshed)\n"
                f"Retry Interval: {parts[4]} seconds (Time to wait before retrying a failed refresh)\n"
                f"Expire Limit: {parts[5]} seconds (Time before the zone is considered no longer authoritative)\n"
                f"Minimum TTL: {parts[6]} seconds (Minimum TTL for any record in the zone)"
            )
        return formatted_records

    def format_ptr_record(self, records):
        return [f"Pointer Record: {record}" for record in records]

    def format_srv_record(self, records):
        formatted_records = []
        for record in records:
            parts = record.split()
            formatted_records.append(
                f"Service Record: {parts[-1]} (Priority: {parts[0]}, Weight: {parts[1]}, Port: {parts[2]})"
            )
        return formatted_records

    def format_caa_record(self, records):
        return [f"Certification Authority Authorization: {record.split(' ', 2)[1]}={record.split(' ', 2)[2]} (Flags: {record.split(' ', 2)[0]})" for record in records]

    def format_naptr_record(self, records):
        formatted_records = []
        for record in records:
            parts = record.split(' ', 5)
            formatted_records.append(f"NAPTR Record: {parts}")
        return formatted_records

    def format_loc_record(self, records):
        return [f"Location: {record}" for record in records]

    def format_hinfo_record(self, records):
        return [f"Host Information: {record}" for record in records]

    def format_rp_record(self, records):
        return [f"Responsible Person: {record}" for record in records]

    def format_tlsa_record(self, records):
        return [f"TLSA Record: {record}" for record in records]

    def format_sshfp_record(self, records):
        return [f"SSHFP Record: {record}" for record in records]

    def format_spf_record(self, records):
        return [f"SPF Record: {record}" for record in records]

    def format_uri_record(self, records):
        return [f"URI Record: {record}" for record in records]

    def format_dnskey_record(self, records):
        return [f"DNSKEY Record: {record}" for record in records]

    def format_rrsig_record(self, records):
        return [f"RRSIG Record: {record}" for record in records]

    def format_ds_record(self, records):
        return [f"DS Record: {record}" for record in records]

    def format_nsec_record(self, records):
        return [f"NSEC Record: {record}" for record in records]

    def format_nsec3_record(self, records):
        return [f"NSEC3 Record: {record}" for record in records]

    def format_hip_record(self, records):
        return [f"HIP Record: {record}" for record in records]

    def format_dname_record(self, records):
        return [f"DNAME Record: {record}" for record in records]

    def format_cds_record(self, records):
        return [f"CDS Record: {record}" for record in records]

    def format_cdnskey_record(self, records):
        return [f"CDNSKEY Record: {record}" for record in records]

    def format_openpgpkey_record(self, records):
        return ["OpenPGP Key: {record}" for record in records]

    def format_tkey_record(self, records):
        return ["TKEY Record: DNS metaqueries are not allowed."]

    def format_tsig_record(self, records):
        return ["TSIG Record: DNS metaqueries are not allowed."]

    def format_apl_record(self, records):
        return [f"Address Prefix List: {record}" for record in records]

    def format_afsdb_record(self, records):
        return [f"AFS Database: {record}" for record in records]

    def format_x25_record(self, records):
        return [f"X.25 Address: {record}" for record in records]

    def format_isdn_record(self, records):
        return [f"ISDN Address: {record}" for record in records]

    def format_rt_record(self, records):
        return [f"Route Through: {record}" for record in records]

    def format_nsap_record(self, records):
        return [f"NSAP Address: {record}" for record in records]

    def format_smimea_record(self, records):
        return [f"S/MIMEA Certificate Association: {record}" for record in records]

    def format_ipseckey_record(self, records):
        return [f"IPSEC Key: {record}" for record in records]

    def format_talink_record(self, records):
        return ["TALINK Record: DNS resource record type is unknown."]

    def format_ninfo_record(self, records):
        return [f"Zone Status Information: {record}" for record in records]

    def format_rkey_record(self, records):
        return ["RKEY Record: DNS resource record type is unknown."]

    def enumerate_dns(self, scan_type="normal"):
        """Query DNS records based on the selected scan type."""
        results = {}
        record_types = self.normal_record_types if scan_type == "normal" else self.absolute_record_types

        for record_type in record_types:
            records = self.query_record(record_type)
            results[record_type] = self.format_record(record_type, records)
        return results

    def run(self):
        """Run the DNS enumeration based on user's choice."""
        print("Select scan type:")
        print("1. Normal Scan (Common DNS records)")
        print("2. Absolute Scan (All possible DNS records)")
        choice = input("Enter 1 or 2: ")

        scan_type = "normal" if choice == "1" else "absolute"
        print(f"\nEnumerating DNS records for domain: {self.domain} using {'Normal Scan' if scan_type == 'normal' else 'Absolute Scan'}")

        dns_records = self.enumerate_dns(scan_type)

        # Enhanced output with clarification
        for record_type, records in dns_records.items():
            print(f"\n{record_type} Records:")
            for record in records:
                print(f"  {record}")

if __name__ == "__main__":
    domain = input("Enter domain to enumerate: ")
    dns_enum = DNSEnumerator(domain)
    dns_enum.run()
