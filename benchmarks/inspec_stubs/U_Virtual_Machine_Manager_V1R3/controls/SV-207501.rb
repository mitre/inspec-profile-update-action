control 'SV-207501' do
  title 'The VMM must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during de-aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Ensuring the confidentiality of transmitted information requires the VMM to take measures in preparing information during reception. This can be accomplished via access control and encryption.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When receiving data, VMMs need to leverage protection mechanisms such as TLS, SSL VPNs, or IPSEC.'
  desc 'check', 'Verify the VMM maintains the confidentiality and integrity of information during reception.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to maintain the confidentiality and integrity of information during reception.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7758r365907_chk'
  tag severity: 'medium'
  tag gid: 'V-207501'
  tag rid: 'SV-207501r854675_rule'
  tag stig_id: 'SRG-OS-000426-VMM-001720'
  tag gtitle: 'SRG-OS-000426'
  tag fix_id: 'F-7758r365908_fix'
  tag 'documentable'
  tag legacy: ['V-57303', 'SV-71563']
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
