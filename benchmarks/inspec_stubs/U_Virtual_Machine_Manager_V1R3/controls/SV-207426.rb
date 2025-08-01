control 'SV-207426' do
  title 'In the event of a system failure, the VMM must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the VMM or a component of the system.

Preserving VMM state information helps to facilitate VMM restart and return to the operational mode of the organization with less disruption of mission/business processes.'
  desc 'check', 'Verify the VMM preserves any information necessary, in the event of a system failure, to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to preserve any information necessary, in the event of a system failure, to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7683r365688_chk'
  tag severity: 'medium'
  tag gid: 'V-207426'
  tag rid: 'SV-207426r379318_rule'
  tag stig_id: 'SRG-OS-000269-VMM-000950'
  tag gtitle: 'SRG-OS-000269'
  tag fix_id: 'F-7683r365689_fix'
  tag 'documentable'
  tag legacy: ['SV-71313', 'V-57053']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
