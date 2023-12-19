control 'SV-205213' do
  title 'If the DNS server is using SIG(0), the DNS server implementation must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected transactions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates. 

SIG(0) relies on PKI-based authentication, so if SIG(0) is being used, this requirement is applicable.'
  desc 'check', 'If the DNS server is using SIG(0), review the DNS server implementation configuration to determine if the DNS server only allows the use of DoD PKI-established certificate authorities for verification of the establishment of protected transactions. If the DNS server allows the use of other certificate authorities, this is a finding.'
  desc 'fix', 'Configure the DNS server to only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected transactions.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5480r392552_chk'
  tag severity: 'medium'
  tag gid: 'V-205213'
  tag rid: 'SV-205213r879798_rule'
  tag stig_id: 'SRG-APP-000427-DNS-000060'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-5480r392553_fix'
  tag 'documentable'
  tag legacy: ['SV-69133', 'V-54887']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
