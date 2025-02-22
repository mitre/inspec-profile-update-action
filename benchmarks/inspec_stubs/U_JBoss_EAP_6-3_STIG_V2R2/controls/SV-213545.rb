control 'SV-213545' do
  title 'JBoss must be configured to use DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.  The application server must only allow the use of DoD PKI-established certificate authorities for verification.'
  desc 'check', 'Locate the cacerts file for the JVM.  This can be done using the appropriate find command for the OS and change to the directory where the cacerts file is located.

To view the certificates stored within this file, execute the java command "keytool -list -v -keystore ./cacerts".
Verify that the Certificate Authority (CA) for each certificate is DoD-approved.

If any certificates have a CA that are not DoD-approved, this is a finding.'
  desc 'fix', 'Locate the cacerts file for the JVM.  This can be done using the appropriate find command for the OS and change to the directory where the cacerts file is located.

Remove the certificates that have a CA that is non-DoD approved, and import DoD CA-approved certificates.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14768r296301_chk'
  tag severity: 'medium'
  tag gid: 'V-213545'
  tag rid: 'SV-213545r615939_rule'
  tag stig_id: 'JBOS-AS-000625'
  tag gtitle: 'SRG-APP-000427-AS-000264'
  tag fix_id: 'F-14766r296302_fix'
  tag 'documentable'
  tag legacy: ['SV-76807', 'V-62317']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
