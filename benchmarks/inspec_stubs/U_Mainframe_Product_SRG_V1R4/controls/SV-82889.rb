control 'SV-82889' do
  title 'The Mainframe Product, when using PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. 

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. 

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', 'If the Mainframe Product uses an external security manager (ESM) for all account management, this is not applicable.

Examine user account management configurations.

If the Mainframe Product  account management  is not configured to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor when using PKI-based authentication, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings  to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor when using PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68931r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68399'
  tag rid: 'SV-82889r1_rule'
  tag stig_id: 'SRG-APP-000175-MFP-000242'
  tag gtitle: 'SRG-APP-000175-MFP-000242'
  tag fix_id: 'F-74515r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
