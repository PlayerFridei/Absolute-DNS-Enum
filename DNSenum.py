import dns.resolver

class DNSEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()

        # Record types for Normal and Absolute scans
        self.normal_record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        # Full list of supported DNS record types from dnspython
        self.absolute_record_types = [
            'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR', 'NULL', 'WKS', 
            'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP', 'AFSDB', 'X25', 'ISDN', 'RT', 
            'NSAP', 'NSAP-PTR', 'SIG', 'KEY', 'PX', 'GPOS', 'AAAA', 'LOC', 'NXT', 
            'SRV', 'NAPTR', 'KX', 'CERT', 'A6', 'DNAME', 'OPT', 'APL', 'DS', 'SSHFP', 
            'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 
            'TLSA', 'SMIMEA', 'HIP', 'NINFO', 'CDS', 'CDNSKEY', 'OPENPGPKEY', 'CSYNC', 
            'ZONEMD', 'SVCB', 'HTTPS', 'SPF', 'UNSPEC', 'NID', 'L32', 'L64', 'LP', 
            'EUI48', 'EUI64', 'TKEY', 'TSIG', 'IXFR', 'AXFR', 'MAILB', 'MAILA', 
            'ANY', 'URI', 'CAA', 'AVC', 'AMTRELAY', 'TA', 'DLV'
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
            'MD': self.format_md_record,
            'MF': self.format_mf_record,
            'MB': self.format_mb_record,
            'MG': self.format_mg_record,
            'MR': self.format_mr_record,
            'NULL': self.format_null_record,
            'WKS': self.format_wks_record,
            'HINFO': self.format_hinfo_record,
            'MINFO': self.format_minfo_record,
            'RP': self.format_rp_record,
            'AFSDB': self.format_afsdb_record,
            'X25': self.format_x25_record,
            'ISDN': self.format_isdn_record,
            'RT': self.format_rt_record,
            'NSAP': self.format_nsap_record,
            'NSAP-PTR': self.format_nsap_ptr_record,
            'SIG': self.format_sig_record,
            'KEY': self.format_key_record,
            'PX': self.format_px_record,
            'GPOS': self.format_gpos_record,
            'LOC': self.format_loc_record,
            'NXT': self.format_nxt_record,
            'NAPTR': self.format_naptr_record,
            'KX': self.format_kx_record,
            'CERT': self.format_cert_record,
            'A6': self.format_a6_record,
            'DNAME': self.format_dname_record,
            'OPT': self.format_opt_record,
            'APL': self.format_apl_record,
            'DS': self.format_ds_record,
            'SSHFP': self.format_sshfp_record,
            'IPSECKEY': self.format_ipseckey_record,
            'RRSIG': self.format_rrsig_record,
            'NSEC': self.format_nsec_record,
            'DNSKEY': self.format_dnskey_record,
            'DHCID': self.format_dhcid_record,
            'NSEC3': self.format_nsec3_record,
            'NSEC3PARAM': self.format_nsec3param_record,
            'TLSA': self.format_tlsa_record,
            'SMIMEA': self.format_smimea_record,
            'HIP': self.format_hip_record,
            'NINFO': self.format_ninfo_record,
            'CDS': self.format_cds_record,
            'CDNSKEY': self.format_cdnskey_record,
            'OPENPGPKEY': self.format_openpgpkey_record,
            'CSYNC': self.format_csync_record,
            'ZONEMD': self.format_zonemd_record,
            'SVCB': self.format_svcb_record,
            'HTTPS': self.format_https_record,
            'SPF': self.format_spf_record,
            'UNSPEC': self.format_unspec_record,
            'NID': self.format_nid_record,
            'L32': self.format_l32_record,
            'L64': self.format_l64_record,
            'LP': self.format_lp_record,
            'EUI48': self.format_eui48_record,
            'EUI64': self.format_eui64_record,
            'TKEY': self.format_tkey_record,
            'TSIG': self.format_tsig_record,
            'IXFR': self.format_ixfr_record,
            'AXFR': self.format_axfr_record,
            'MAILB': self.format_mailb_record,
            'MAILA': self.format_maila_record,
            'ANY': self.format_any_record,
            'URI': self.format_uri_record,
            'AVC': self.format_avc_record,
            'AMTRELAY': self.format_amtrelay_record,
            'TA': self.format_ta_record,
            'DLV': self.format_dlv_record
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
                f"Refresh Interval: {parts[3]} seconds\n"
                f"Retry Interval: {parts[4]} seconds\n"
                f"Expire Limit: {parts[5]} seconds\n"
                f"Minimum TTL: {parts[6]} seconds"
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

    # Define similar format functions for all the other record types, such as:
    def format_md_record(self, records): return [f"MD Record: {record}" for record in records]
    def format_mf_record(self, records): return [f"MF Record: {record}" for record in records]
    def format_mb_record(self, records): return [f"MB Record: {record}" for record in records]
    def format_mg_record(self, records): return [f"MG Record: {record}" for record in records]
    def format_mr_record(self, records): return [f"MR Record: {record}" for record in records]
    def format_null_record(self, records): return [f"NULL Record: {record}" for record in records]
    def format_wks_record(self, records): return [f"WKS Record: {record}" for record in records]
    def format_hinfo_record(self, records): return [f"HINFO Record: {record}" for record in records]
    def format_minfo_record(self, records): return [f"MINFO Record: {record}" for record in records]
    def format_rp_record(self, records): return [f"RP Record: {record}" for record in records]
    def format_afsdb_record(self, records): return [f"AFSDB Record: {record}" for record in records]
    def format_x25_record(self, records): return [f"X25 Record: {record}" for record in records]
    def format_isdn_record(self, records): return [f"ISDN Record: {record}" for record in records]
    def format_rt_record(self, records): return [f"RT Record: {record}" for record in records]
    def format_nsap_record(self, records): return [f"NSAP Record: {record}" for record in records]
    def format_nsap_ptr_record(self, records): return [f"NSAP-PTR Record: {record}" for record in records]
    def format_sig_record(self, records): return [f"SIG Record: {record}" for record in records]
    def format_key_record(self, records): return [f"KEY Record: {record}" for record in records]
    def format_px_record(self, records): return [f"PX Record: {record}" for record in records]
    def format_gpos_record(self, records): return [f"GPOS Record: {record}" for record in records]
    def format_loc_record(self, records): return [f"LOC Record: {record}" for record in records]
    def format_nxt_record(self, records): return [f"NXT Record: {record}" for record in records]
    def format_naptr_record(self, records): return [f"NAPTR Record: {record}" for record in records]
    def format_kx_record(self, records): return [f"KX Record: {record}" for record in records]
    def format_cert_record(self, records): return [f"CERT Record: {record}" for record in records]
    def format_a6_record(self, records): return [f"A6 Record: {record}" for record in records]
    def format_dname_record(self, records): return [f"DNAME Record: {record}" for record in records]
    def format_opt_record(self, records): return [f"OPT Record: {record}" for record in records]
    def format_apl_record(self, records): return [f"APL Record: {record}" for record in records]
    def format_ds_record(self, records): return [f"DS Record: {record}" for record in records]
    def format_sshfp_record(self, records): return [f"SSHFP Record: {record}" for record in records]
    def format_ipseckey_record(self, records): return [f"IPSECKEY Record: {record}" for record in records]
    def format_rrsig_record(self, records): return [f"RRSIG Record: {record}" for record in records]
    def format_nsec_record(self, records): return [f"NSEC Record: {record}" for record in records]
    def format_dnskey_record(self, records): return [f"DNSKEY Record: {record}" for record in records]
    def format_dhcid_record(self, records): return [f"DHCID Record: {record}" for record in records]
    def format_nsec3_record(self, records): return [f"NSEC3 Record: {record}" for record in records]
    def format_nsec3param_record(self, records): return [f"NSEC3PARAM Record: {record}" for record in records]
    def format_tlsa_record(self, records): return [f"TLSA Record: {record}" for record in records]
    def format_smimea_record(self, records): return [f"SMIMEA Record: {record}" for record in records]
    def format_hip_record(self, records): return [f"HIP Record: {record}" for record in records]
    def format_ninfo_record(self, records): return [f"NINFO Record: {record}" for record in records]
    def format_cds_record(self, records): return [f"CDS Record: {record}" for record in records]
    def format_cdnskey_record(self, records): return [f"CDNSKEY Record: {record}" for record in records]
    def format_openpgpkey_record(self, records): return [f"OPENPGPKEY Record: {record}" for record in records]
    def format_csync_record(self, records): return [f"CSYNC Record: {record}" for record in records]
    def format_zonemd_record(self, records): return [f"ZONEMD Record: {record}" for record in records]
    def format_svcb_record(self, records): return [f"SVCB Record: {record}" for record in records]
    def format_https_record(self, records): return [f"HTTPS Record: {record}" for record in records]
    def format_spf_record(self, records): return [f"SPF Record: {record}" for record in records]
    def format_unspec_record(self, records): return [f"UNSPEC Record: {record}" for record in records]
    def format_nid_record(self, records): return [f"NID Record: {record}" for record in records]
    def format_l32_record(self, records): return [f"L32 Record: {record}" for record in records]
    def format_l64_record(self, records): return [f"L64 Record: {record}" for record in records]
    def format_lp_record(self, records): return [f"LP Record: {record}" for record in records]
    def format_eui48_record(self, records): return [f"EUI48 Record: {record}" for record in records]
    def format_eui64_record(self, records): return [f"EUI64 Record: {record}" for record in records]
    def format_tkey_record(self, records): return [f"TKEY Record: {record}" for record in records]
    def format_tsig_record(self, records): return [f"TSIG Record: {record}" for record in records]
    def format_ixfr_record(self, records): return [f"IXFR Record: {record}" for record in records]
    def format_axfr_record(self, records): return [f"AXFR Record: {record}" for record in records]
    def format_mailb_record(self, records): return [f"MAILB Record: {record}" for record in records]
    def format_maila_record(self, records): return [f"MAILA Record: {record}" for record in records]
    def format_any_record(self, records): return [f"ANY Record: {record}" for record in records]
    def format_uri_record(self, records): return [f"URI Record: {record}" for record in records]
    def format_avc_record(self, records): return [f"AVC Record: {record}" for record in records]
    def format_amtrelay_record(self, records): return [f"AMTRELAY Record: {record}" for record in records]
    def format_ta_record(self, records): return [f"TA Record: {record}" for record in records]
    def format_dlv_record(self, records): return [f"DLV Record: {record}" for record in records]

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
