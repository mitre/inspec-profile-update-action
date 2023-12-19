control 'SV-205240' do
  title 'The DNS implementation must be conformant to the IETF DNS specification.'
  desc 'Any DNS implementation must be designed to be able to conform to the Internet Engineering Task Force (IETF) specification. DoD utilizes many different DNS servers, and it is essential that core capabilities of all are compatible. DNS servers that do not provide services compliant to the DNS RFCs may cause denial of service issues.

The server must be compliant to the IETF standard so as to provide the right balance between performance and integrity of the DNS system.'
  desc 'check', "Review DNS implementation documentation to determine whether the DNS system has capabilities compliant to IETF RFC-1034 (Domain Names-Concepts and Facilities), RFC-1035 (Domain Names-Implementation and Specification), and subsequent RFCs. Systems using DNSSEC (DNS Security Extensions) should be compliant to RFC-4033 (DNS Security Introduction and Requirements), RFC-4024 (Resource Records for the DNS Security Extensions), RFC-4035 (Protocol Modifications for the DNS security Extensions), RFC-5155 (DNS Security (DNSSEC) Hashed Authenticated Denial of Existence) and related RFCs. 

A DNS implementation may also be found non-compliant by empirical analysis, i.e., by experimentally querying and examine the answer. For example, a DNS implementation may not answer a query for the 'NS' resource record type with a CNAME reply.

If the implementation does not comply to the IETF DNS RFCs, this is a finding."
  desc 'fix', "Configure the DNS implementation to be compliant to the IETF specifications for DNS.

Protect DNS transactions, such as update of DNS name resolution data and data replication that involve DNS nodes within an enterprise's control. The transactions should be protected using hash-based message authentication codes based on shared secrets, as outlined in Internet Engineering Task Force's (IETF) Transaction Signature (TSIG) specification.

Protect the ubiquitous DNS query/response transaction that could involve any DNS node in the global Internet using digital signatures based on asymmetric cryptography, as outlined in IETF's Domain Name System Security Extension (DNSSEC) specification."
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5507r392633_chk'
  tag severity: 'medium'
  tag gid: 'V-205240'
  tag rid: 'SV-205240r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000097'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5507r392634_fix'
  tag 'documentable'
  tag legacy: ['SV-69187', 'V-54941']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
