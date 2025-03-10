control 'SV-205176' do
  title 'A DNS server implementation must provide additional data origin artifacts along with the authoritative data the system returns in response to external name/address resolution queries.'
  desc 'The underlying feature in the major threat associated with DNS query/response (i.e., forged response or response failure) is the integrity of DNS data returned in the response. The security objective is to verify the integrity of each response received. An integral part of integrity verification is to ensure that valid data has originated from the right source. Establishing trust in the source is called data origin authentication. 

The security objectives—and consequently the security services—that are required for securing the DNS query/response transaction are data origin authentication and data integrity verification. 

The specification for a digital signature mechanism in the context of the DNS infrastructure is in IETF’s DNSSEC standard. In DNSSEC, trust in the public key (for signature verification) of the source is established not by going to a third party or a chain of third parties (as in public key infrastructure [PKI] chaining), but by starting from a trusted zone (such as the root zone) and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent. The public key of the trusted zone is called the trust anchor.'
  desc 'check', "Review the zones hosted by the DNS server. Verify each of the zones have been digitally signed.

To determine if the zones have been digitally signed, verify the existence of an RRSET for each zone, which will include, at a minimum, an RRType RRSIG (Resource Record Signature) as well as an RRType DNSKEY and RRType NSEC (Next Secure). 

If the DNS server's zones do not contain these additional RRs along with the regular RRs, this is a finding."
  desc 'fix', 'Generate an RRSET for each zone hosted by the DNS server to include an RRSIG, DNSKEY and NSEC for each zone.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5443r392444_chk'
  tag severity: 'medium'
  tag gid: 'V-205176'
  tag rid: 'SV-205176r879633_rule'
  tag stig_id: 'SRG-APP-000213-DNS-000024'
  tag gtitle: 'SRG-APP-000213'
  tag fix_id: 'F-5443r392445_fix'
  tag 'documentable'
  tag legacy: ['SV-69061', 'V-54815']
  tag cci: ['CCI-001178']
  tag nist: ['SC-20 a']
end
