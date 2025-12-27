control 'SV-214169' do
  title 'A DNS server implementation must provide the means to indicate the security status of child zones.'
  desc "If name server replies are invalid or cannot be validated, many networking functions and communication would be adversely affected. With DNS, the presence of Delegation Signer (DS) records associated with child zones informs clients of the security status of child zones. These records are crucial to the DNSSEC chain of trust model. Each parent domain's DS record is used to verify the DNSKEY record in its subdomain, from the top of the DNS hierarchy down.

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS, to map between host/service names and network addresses, must provide other means to assure the authenticity and integrity of response data. 

In DNS, trust in the public key of the source is established by starting from a trusted name server and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent. 

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and Domain Name System Security Extensions (DNSSEC). 

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor. A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate. In DNS, a trust anchor is a DNSKEY that is placed into a validating resolver so the validator can cryptographically validate the results for a given request back to a known public key (the trust anchor). 

An example means to indicate the security status of child subspaces is through the use of delegation signer (DS) resource records in the DNS.

Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Without path validation and a chain of trust, there can be no trust that the data integrity authenticity has been maintained during a transaction."
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Infoblox systems within a Grid configuration automatically publish DS records to the parent zone when the child zone is signed.

If all name servers for parent and child zones are within an Infoblox Grid, this is not a finding.

Review the parent zones hosted on the Infoblox server for which the child zone is NOTE on the same Infoblox Grid. Each zone must include the Delegation Signer (DS) records for the child zone.

If DS records are not published in the parent zone for DNSSEC signed child zones, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Zones tab.

Select the parent zone, and use the DNSSEC drop-down menu to select "Import Keyset".
Add the child zone DS RRs and select "Import".'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15384r295773_chk'
  tag severity: 'medium'
  tag gid: 'V-214169'
  tag rid: 'SV-214169r612370_rule'
  tag stig_id: 'IDNS-7X-000220'
  tag gtitle: 'SRG-APP-000214-DNS-000025'
  tag fix_id: 'F-15382r295774_fix'
  tag 'documentable'
  tag legacy: ['V-68533', 'SV-83023']
  tag cci: ['CCI-001179']
  tag nist: ['SC-20 b']
end
