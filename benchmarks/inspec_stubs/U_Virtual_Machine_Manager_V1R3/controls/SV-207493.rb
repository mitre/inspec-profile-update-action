control 'SV-207493' do
  title 'The VMM must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.

This requirement is not applicable to VMM-internal sessions between components not identified as "Key Terrain" for "Non-Person Entities" per DoD policy.'
  desc 'check', 'Verify the VMM only allows the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7750r365883_chk'
  tag severity: 'medium'
  tag gid: 'V-207493'
  tag rid: 'SV-207493r854667_rule'
  tag stig_id: 'SRG-OS-000403-VMM-001640'
  tag gtitle: 'SRG-OS-000403'
  tag fix_id: 'F-7750r365884_fix'
  tag 'documentable'
  tag legacy: ['V-57287', 'SV-71547']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
