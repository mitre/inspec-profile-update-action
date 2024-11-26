control 'SV-96075' do
  title 'The WebSphere Application Server must use signer for DoD-issued certificates.'
  desc 'The cornerstone of PKI is the private key used to encrypt or digitally sign information. The key by itself is a cryptographic value that does not contain specific user information, but the key can be mapped to a user. Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

Application servers must provide the capability to utilize and meet requirements of the DoD Enterprise PKI infrastructure for application authentication.'
  desc 'check', 'Navigate to Security >> SSl certificate and key management >> SSL Configurations >> CellDefaultSSLSettings >> KeyStores and certificates.

Click on cell default trust store.

Click on "Signer Certificates".

If no DoD root or intermediate certificates are present, this is a finding.'
  desc 'fix', 'Obtain the signer certificate either as Base 64 encoded ASCII file, or as binary DER data.

Navigate to Security >> SSl certificate and key management >> SSL Configurations >> CellDefaultSSLSettings >> key stores and certificates.

Click on cell default trust store.

Click on "Signer Certificates".

Click "Add".

Enter a new alias for the signer, and the location of the file that stores signer certificate.

For "Data type", choose the type appropriate for the file, either Base64-encoded ASCII data file, or binary DER data.

Click "OK".'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81069r3_chk'
  tag severity: 'medium'
  tag gid: 'V-81361'
  tag rid: 'SV-96075r1_rule'
  tag stig_id: 'WBSP-AS-001260'
  tag gtitle: 'SRG-APP-000177-AS-000126'
  tag fix_id: 'F-88147r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
