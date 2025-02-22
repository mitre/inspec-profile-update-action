control 'SV-96083' do
  title 'The WebSphere Application Server must use DoD-approved Signer Certificates.'
  desc 'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The application server must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc 'check', 'From administrative console, navigate to Security >> SSL Certificates and Key Management >> KeyStores and Certificates.

For each keystore, click on "Signer Certificates".

If any of the certificates are not issued by an approved DoD CA, this is a finding.'
  desc 'fix', 'Utilize DoD certificates that have been issued by a DoD PKI CA.

To replace a non-DoD PKI-established certificate:
From the administrative console, navigate to Security >> SSL Certificates and Key Management >> KeyStores and Certificates.

For each keystore that requires the change:
Import a new certificate by clicking "Import".

Click "keystore" file.

Enter the location of the new certificate.

Specify the type of keystore and keystore password.

Specify alias information.

Click "Apply". 

After the certificate is imported, click on "Replace" to replace the original certificate with the new certificate.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81079r3_chk'
  tag severity: 'medium'
  tag gid: 'V-81369'
  tag rid: 'SV-96083r1_rule'
  tag stig_id: 'WBSP-AS-001370'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag fix_id: 'F-88155r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
