control 'SV-96089' do
  title 'The WebSphere Application Server personal certificates in all keystores must be issued by an approved DoD CA.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates. The application server must only allow the use of DoD PKI-established certificate authorities for verification.'
  desc 'check', 'Review System Security Plan documentation for a list of DoD-approved CAs. 

From administrative console, navigate to Security >> SSL Certificates and Key Management >> KeyStores and Certificates.

For each keystore, click on "Personal Certificates".

If any of the certificates are not issued by an approved DoD CA, this is a finding.'
  desc 'fix', 'Utilize DoD certificates that have been issued by an approved DoD PKI CA.

To replace a non-DoD PKI-established certificate:
From the administrative console, navigate to Security >> SSL Certificates and Key Management >> KeyStores and Certificates.

For each keystores that requires the change:
Import a new certificate by clicking "Import".

Click "keystore" file.

Enter the location of the new certificate.

Specify the type of keystore and keystore password.

Specify alias information.

Click "Apply".

After the certificate is imported, click on "Replace" to replace the original certificate with the new certificate.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81085r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81375'
  tag rid: 'SV-96089r1_rule'
  tag stig_id: 'WBSP-AS-001460'
  tag gtitle: 'SRG-APP-000427-AS-000264'
  tag fix_id: 'F-88161r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
