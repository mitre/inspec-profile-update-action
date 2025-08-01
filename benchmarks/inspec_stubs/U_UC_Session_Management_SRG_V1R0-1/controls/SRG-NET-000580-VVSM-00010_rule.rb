control 'SRG-NET-000580-VVSM-00010_rule' do
  title 'When using PKI, the Unified Communications Session Manager must validate certificates used for Transport Layer Security (TLS) functions by performing RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. 

Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', 'Verify the Unified Communications Session Manager, when using PKI, is configured to validate certificates using RFC 5280 path validation.

If the Unified Communications Session Manager is not configured to validate certificates using RFC 5280 path validation, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager, when using PKI, to validate certificates using RFC 5280 path validation.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000580-VVSM-00010_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000580-VVSM-00010'
  tag rid: 'SRG-NET-000580-VVSM-00010_rule'
  tag stig_id: 'SRG-NET-000580-VVSM-00010'
  tag gtitle: 'SRG-NET-000580-VVSM-00010'
  tag fix_id: 'F-SRG-NET-000580-VVSM-00010_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
