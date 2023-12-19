control 'SV-69069' do
  title 'A DNS server implementation must provide the means to enable verification of a chain of trust among parent and child domains (if the child supports secure resolution services).'
  desc "If name server replies are invalid or cannot be validated, many networking functions and communication would be adversely affected. With DNS, the presence of Delegation Signer (DS) records associated with child zones informs clients of the security status of child zones. These records are crucial to the DNSSEC chain of trust model. Each parent domain's DS record is used to verify the DNSKEY record in its subdomain, from the top of the DNS hierarchy down.

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS to map between host/service names and network addresses must provide other means to assure the authenticity and integrity of response data.

DNSSEC provides the means to verify integrity assurances for the host/service name to network address resolution information obtained through the service. By using the delegation signer (DS) resource records in the DNS, the security status of a child domain can be validated.  The DS resource record is used to identify the DNSSEC signing key of a delegated zone.

Starting from a trusted name server (such as the root name server) and down to the current source of response through successive verifications of signature of the public key of a child by its parent, the chain of trust is established. The public key of the trusted name servers is called the trust anchor. After authenticating the source, the next process DNSSEC calls for is to authenticate the response. This requires that responses consist of not only the requested RRs but also an authenticator associated with them. In DNSSEC, this authenticator is the digital signature of a Resource Record (RR) Set. The digital signature of an RRSet is encapsulated through a special RRType called RRSIG. The DNS client using the trusted public key of the source (whose trust has just been established) then verifies the digital signature to detect if the response is valid or bogus.

This control enables the DNS to obtain origin authentication and integrity verification assurances for the host/service name to network address resolution information obtained through the service.  Without indication of the security status of a child domain and enabling verification of a chain of trust, integrity and availability of the DNS infrastructure cannot be assured."
  desc 'check', "If the system being reviewed is an authoritative server, it must be able to provide records that can be authenticated (DS, RRSIG, etc.).

Compare the child zone's hash stored in the child's DS RR to the hash for the child's zone in the parent's zone information. Verify it is the same hash.

If the hashes do not match, or the child zone is not digitally signed, this is a finding.

If the system is a recursive server, it must be able to pass DNSSEC data and perform DNSSEC validation.

If DNSSEC validation capability is not enabled on a recursive DNS server, this is a finding.

If the hash for child domains is not reflected in the parent zone and the chain of trust is not verifiable, this is a finding."
  desc 'fix', 'Configure a recursive, caching only server with the ability to perform DNSSEC validation.

Configure an authoritative name server to sign all zones and to update the entire chain of trust with the signature.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55445r3_chk'
  tag severity: 'medium'
  tag gid: 'V-54823'
  tag rid: 'SV-69069r1_rule'
  tag stig_id: 'SRG-APP-000215-DNS-000026'
  tag gtitle: 'SRG-APP-000215-DNS-000026'
  tag fix_id: 'F-59681r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
