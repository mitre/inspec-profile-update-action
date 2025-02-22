control 'SV-207578' do
  title 'A BIND 9.x server implementation must provide the means to indicate the security status of child zones.'
  desc "If name server replies are invalid or cannot be validated, many networking functions and communication would be adversely affected. With DNS, the presence of Delegation Signer (DS) records associated with child zones informs clients of the security status of child zones. These records are crucial to the DNSSEC chain of trust model. Each parent domain's DS record is used to verify the DNSKEY record in its subdomain, from the top of the DNS hierarchy down.

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS, to map between host/service names and network addresses, must provide other means to assure the authenticity and integrity of response data.

In DNS, trust in the public key of the source is established by starting from a trusted name server and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and Domain Name System Security Extensions (DNSSEC).

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor. A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate. In DNS, a trust anchor is a DNSKEY that is placed into a validating resolver so the validator can cryptographically validate the results for a given request back to a known public key (the trust anchor).

An example means to indicate the security status of child subspaces is through the use of delegation signer (DS) resource records in the DNS.

Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Without path validation and a chain of trust, there can be no trust that the data integrity authenticity has been maintained during a transaction."
  desc 'check', 'If the server is in a classified network, this is Not Applicable.

Verify that there is a DS record set for each child zone defined in "/etc/named.conf" file.

For each child zone listed in "/etc/named.conf" file, verify there is a corresponding "dsset-zone_name" file.

If any child zone does not have a corresponding DS record set, this is a finding.'
  desc 'fix', 'Sign each child zone. During the zone signing process, ensure that a DS record is created and is stored on the Parent zone name server.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7833r283788_chk'
  tag severity: 'medium'
  tag gid: 'V-207578'
  tag rid: 'SV-207578r612253_rule'
  tag stig_id: 'BIND-9X-001310'
  tag gtitle: 'SRG-APP-000214-DNS-000025'
  tag fix_id: 'F-7833r283789_fix'
  tag 'documentable'
  tag legacy: ['SV-87097', 'V-72473']
  tag cci: ['CCI-001179']
  tag nist: ['SC-20 b']
end
