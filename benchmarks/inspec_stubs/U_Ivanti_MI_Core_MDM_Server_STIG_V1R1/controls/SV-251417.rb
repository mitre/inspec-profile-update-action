control 'SV-251417' do
  title 'The Ivanti MobileIron Core server must only allow the use of DoD PKI established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of TLS certificates.

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).

'
  desc 'check', 'Verify the MDM server is configured with TLS server certificate chain to a DOD certificate Authority.

Go into the Certificate Manager >> System Manager >> Security >> Certificate Management >> Portal HTTPS. Verify DoD certificates are installed.

If DoD digital certificates are not installed on Core, this is a finding.'
  desc 'fix', 'Install DoD digital certificates.

Configure the MDM server. System Manager >> Security >> Certificate Management >> Portal HTTPS. Install DOD certificate chain.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54852r806381_chk'
  tag severity: 'medium'
  tag gid: 'V-251417'
  tag rid: 'SV-251417r806383_rule'
  tag stig_id: 'IMIC-11-010200'
  tag gtitle: 'SRG-APP-000427-UEM-000298'
  tag fix_id: 'F-54805r806382_fix'
  tag satisfies: ['FIA_X509_EXT.1.1(1)']
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
