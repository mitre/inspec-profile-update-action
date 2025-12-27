control 'SV-206478' do
  title 'The Central Log Server, when utilizing PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. 

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. 

This requirement verifies that a certification path to an accepted trust anchor is used to for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

If the Central Log Server is not configured to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  impact 0.7
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6738r285678_chk'
  tag severity: 'high'
  tag gid: 'V-206478'
  tag rid: 'SV-206478r397594_rule'
  tag stig_id: 'SRG-APP-000175-AU-002630'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-6738r285679_fix'
  tag 'documentable'
  tag legacy: ['SV-96001', 'V-81287']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
