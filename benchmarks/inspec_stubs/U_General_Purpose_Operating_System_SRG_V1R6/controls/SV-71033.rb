control 'SV-71033' do
  title 'The operating system must only allow the use of DoD PKI-established certificate authorities for authentication in the establishment of protected sessions to the operating system.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI-certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.'
  desc 'check', 'Verify the operating system only allows the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57343r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56773'
  tag rid: 'SV-71033r2_rule'
  tag stig_id: 'SRG-OS-000403-GPOS-00182'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-61669r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
