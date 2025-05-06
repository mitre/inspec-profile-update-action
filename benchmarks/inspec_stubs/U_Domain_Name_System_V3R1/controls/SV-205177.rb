control 'SV-205177' do
  title 'A DNS server implementation must provide the means to indicate the security status of child zones.'
  desc "If name server replies are invalid or cannot be validated, many networking functions and communication would be adversely affected. With DNS, the presence of Delegation Signer (DS) records associated with child zones informs clients of the security status of child zones. These records are crucial to the DNSSEC chain of trust model. Each parent domain's DS record is used to verify the DNSKEY record in its subdomain, from the top of the DNS hierarchy down.

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS, to map between host/service names and network addresses, must provide other means to assure the authenticity and integrity of response data. 

In DNS, trust in the public key of the source is established by starting from a trusted name server and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent. 

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and Domain Name System Security Extensions (DNSSEC). 

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor. A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate. In DNS, a trust anchor is a DNSKEY that is placed into a validating resolver so the validator can cryptographically validate the results for a given request back to a known public key (the trust anchor). 

An example means to indicate the security status of child subspaces is through the use of delegation signer (DS) resource records in the DNS.

Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Without path validation and a chain of trust, there can be no trust that the data integrity authenticity has been maintained during a transaction."
  desc 'check', "Review the zones hosted by the DNS server. Every zone should have an RRSET which includes the RRTypes of RRSIG, DNSKEY and NSEC. 

If a zone has a child, the RRSET should also include the RRType DS (Delegation Signer) RR, which contain the (hash) public key of child zones.

If the zones hosted by the DNS server do not have any child domains, this is not a finding.

If the zones hosted by the DNS server have child domains, and there is not an RRType DS RR in the zone's RRSET, this is a finding."
  desc 'fix', 'Configure each child zone to upload its DS RRset to the parent zone.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5444r392447_chk'
  tag severity: 'medium'
  tag gid: 'V-205177'
  tag rid: 'SV-205177r879634_rule'
  tag stig_id: 'SRG-APP-000214-DNS-000025'
  tag gtitle: 'SRG-APP-000214'
  tag fix_id: 'F-5444r392448_fix'
  tag 'documentable'
  tag legacy: ['SV-69063', 'V-54817']
  tag cci: ['CCI-001179']
  tag nist: ['SC-20 b']
end
