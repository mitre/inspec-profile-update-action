control 'SV-207500' do
  title 'The VMM must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Ensuring the confidentiality of transmitted information requires the VMM to take measures in preparing information for transmission. This can be accomplished via access control and encryption.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, VMMs need to support transmission protection mechanisms such as TLS, SSL VPNs, or IPSEC.'
  desc 'check', 'Verify the VMM maintains the confidentiality and integrity of information during preparation for transmission.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to maintain the confidentiality and integrity of information during preparation for transmission.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7757r365904_chk'
  tag severity: 'medium'
  tag gid: 'V-207500'
  tag rid: 'SV-207500r854674_rule'
  tag stig_id: 'SRG-OS-000425-VMM-001710'
  tag gtitle: 'SRG-OS-000425'
  tag fix_id: 'F-7757r365905_fix'
  tag 'documentable'
  tag legacy: ['V-57301', 'SV-71561']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
