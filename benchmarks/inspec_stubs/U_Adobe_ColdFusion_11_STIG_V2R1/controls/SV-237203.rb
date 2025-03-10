control 'SV-237203' do
  title 'ColdFusion must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.  The application server must only allow the use of DoD PKI-established certificate authorities for verification. DoD-approved CAs can be found in the “installroot” tool on https://iase.disa.mil or in the Windows certificate store of the Windows Secure Host Baseline image.

ColdFusion uses the underlying JVM and keystore for storing and certificates and for use within connections for data transfer.  These certificates must be checked to ensure the certificates are from DoD PKI-established certificate authorities.'
  desc 'check', 'Locate the cacerts file for the JVM.  This can be done using the appropriate find command for the OS and change to the directory where the cacerts file is located.  To view the certificates stored within this file, execute the java command keytool -list -v -keystore ./cacerts and verify that the Certificate Authority (CA) for each certificate is DoD-approved.

If any certificates have a CA that is not DoD-approved, this is a finding.'
  desc 'fix', 'Locate the cacerts file for the JVM.  This can be done using the appropriate find command for the OS and change to the directory where the cacerts file is located.  Remove the certificates that have a CA that is non-DoD approved and import DoD CA-approved certificates.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40422r641702_chk'
  tag severity: 'medium'
  tag gid: 'V-237203'
  tag rid: 'SV-237203r641704_rule'
  tag stig_id: 'CF11-05-000178'
  tag gtitle: 'SRG-APP-000427-AS-000264'
  tag fix_id: 'F-40385r641703_fix'
  tag 'documentable'
  tag legacy: ['SV-76969', 'V-62479']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
