control 'SV-77321' do
  title 'The Riverbed Optimization System (RiOS) that provides intermediary services for TLS must validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. 

Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', 'Verify that RiOS is configured to validate certificates used for TLS functions by performing certificate path validation.

Navigate to the device Management Console.
Navigate to Configure >> Optimization >> CRL Management.
Verify that "Enable Automatic CRL Polling For CAs" and "Enable Automatic CRL Polling For Peering CAs" is checked.

If "Enable Automatic CRL Polling For CAs" and/or "Enable Automatic CRL Polling For Peering CAs" is not set, this is a finding.'
  desc 'fix', 'Configure RiOS to validate certificates used for TLS functions by performing certificate path validation.

Navigate to the device Management Console.
Navigate to Configure >> Optimization >> CRL Management.
Set the checkbox for "Enable Automatic CRL Polling For CAs".
Set the checkbox for "Enable Automatic CRL Polling For Peering CAs".
Click "Apply".
Navigate to the top of the web page and click "Save".'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 ALG'
  tag check_id: 'C-63625r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62831'
  tag rid: 'SV-77321r1_rule'
  tag stig_id: 'RICX-AG-000098'
  tag gtitle: 'SRG-NET-000164-ALG-000100'
  tag fix_id: 'F-68749r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
