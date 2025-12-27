control 'SV-234573' do
  title 'The UEM server must only allow the use of DoD PKI established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of TLS certificates. 

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA). 

Satisfies:FIA_X509_EXT.1.1(1)'
  desc 'check', 'Verify the UEM server allows only DoD-PKI established certificate authorities for verification of the establishment of protected sessions.

If the UEM server does not allow only DoD-PKI established certificate authorities for verification of the establishment of protected sessions, this is a finding.'
  desc 'fix', 'Configure the UEM server to allow only DoD-PKI established certificate authorities for verification of the establishment of protected sessions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37758r851645_chk'
  tag severity: 'medium'
  tag gid: 'V-234573'
  tag rid: 'SV-234573r879798_rule'
  tag stig_id: 'SRG-APP-000427-UEM-000298'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-37723r615354_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
