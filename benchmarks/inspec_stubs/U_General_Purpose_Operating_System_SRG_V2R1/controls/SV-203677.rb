control 'SV-203677' do
  title 'In the event of a system failure, the operating system must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. 

Preserving operating system state information helps to facilitate operating system restart and return to the operational mode of the organization with least disruption to mission/business processes.'
  desc 'check', 'Verify, in the event of a system failure, the operating system preserves any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes, in the event of a system failure.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3802r374918_chk'
  tag severity: 'medium'
  tag gid: 'V-203677'
  tag rid: 'SV-203677r379318_rule'
  tag stig_id: 'SRG-OS-000269-GPOS-00103'
  tag gtitle: 'SRG-OS-000269'
  tag fix_id: 'F-3802r374919_fix'
  tag 'documentable'
  tag legacy: ['V-57191', 'SV-71451']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
