control 'SV-203622' do
  title 'The operating system, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', 'Verify the operating system, for PKI-based authentication, validates certificates by constructing a certification path (which includes status information) to an accepted trust anchor. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system, for PKI-based authentication, to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3747r557590_chk'
  tag severity: 'medium'
  tag gid: 'V-203622'
  tag rid: 'SV-203622r557592_rule'
  tag stig_id: 'SRG-OS-000066-GPOS-00034'
  tag gtitle: 'SRG-OS-000066'
  tag fix_id: 'F-3747r557591_fix'
  tag 'documentable'
  tag legacy: ['V-56683', 'SV-70943']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
