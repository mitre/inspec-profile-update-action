control 'SV-233909' do
  title 'The Infoblox DNS server implementation must provide the means to indicate the security status of child zones.'
  desc "If name server replies are invalid or cannot be validated, many networking functions and communication would be adversely affected. With DNS, the presence of Delegation Signer (DS) records associated with child zones informs clients of the security status of child zones. These records are crucial to the Domain Name System Security Extension (DNSSEC) chain of trust model. Each parent domain's DS record is used to verify the DNSKEY record in its subdomain, from the top of the DNS hierarchy down.

A DNS server is an example of an information system providing name/address resolution service. Digital signatures and cryptographic keys are examples of additional artifacts. DNS resource records are examples of authoritative data. Applications other than the DNS, to map between host/service names and network addresses, must provide other means to ensure the authenticity and integrity of response data. 

In DNS, trust in the public key of the source is established by starting from a trusted name server and establishing the chain of trust down to the current source of response through successive verifications of signature of the public key of a child by its parent. 

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. 

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor. A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate. In DNS, a trust anchor is a DNSKEY that is placed into a validating resolver so the validator can cryptographically validate the results for a given request back to a known public key (the trust anchor). 

An example means to indicate the security status of child subspaces is through the use of DS resource records in the DNS.

Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Without path validation and a chain of trust, there can be no trust that the data integrity authenticity has been maintained during a transaction."
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.  

Infoblox systems within a Grid configuration automatically publish DS records to the parent zone when the child zone is signed. 

If all name servers for parent and child zones are within an Infoblox Grid, this is not a finding. 

1. Review the parent zones hosted on the Infoblox server for which the child zone is on the same Infoblox Grid.  
2. Verify that each zone includes the DS records for the child zone.  

If DS records are not published in the parent zone for DNSSEC signed zones, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Zones tab. 
2. Select the parent zone and use the DNSSEC drop-down menu to select "Import Keyset".  
3. Add the child zone DS resource records (RRs) and select "Import".  
4. Click "Save" and "Close".'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37094r611247_chk'
  tag severity: 'medium'
  tag gid: 'V-233909'
  tag rid: 'SV-233909r621666_rule'
  tag stig_id: 'IDNS-8X-700004'
  tag gtitle: 'SRG-APP-000214-DNS-000025'
  tag fix_id: 'F-37059r611248_fix'
  tag 'documentable'
  tag cci: ['CCI-001179']
  tag nist: ['SC-20 b']
end
