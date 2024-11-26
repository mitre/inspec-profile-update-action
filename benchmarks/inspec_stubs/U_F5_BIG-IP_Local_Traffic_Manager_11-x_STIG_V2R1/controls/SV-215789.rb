control 'SV-215789' do
  title 'The BIG-IP Core implementation must be configured to only allow the use of DoD-approved PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted certificate authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of TLS/TLS certificates.

This requirement focuses on communications protection for the application session rather than for the network packet.'
  desc 'check', 'Verify the BIG-IP Core is configured to allow the use of DoD-approved PKI-established certificate authorities for verification of the establishment of protected sessions. 

Navigate to the BIG-IP System manager >> System >> File Management >> SSL Certificate List.

Validate that an approved DOD CA Bundle is listed.

If the BIG-IP Core is not configured to use DoD-approved PKI-established certificate authorities for verification of the establishment of protected sessions, this is a finding.'
  desc 'fix', 'Configure the BIG-IP Core to only allow the use of DoD-approved PKI-established certificate authorities for verification of the establishment of protected sessions.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16981r291180_chk'
  tag severity: 'medium'
  tag gid: 'V-215789'
  tag rid: 'SV-215789r557356_rule'
  tag stig_id: 'F5BI-LT-000213'
  tag gtitle: 'SRG-NET-000355-ALG-000117'
  tag fix_id: 'F-16979r291181_fix'
  tag 'documentable'
  tag legacy: ['V-60359', 'SV-74789']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
