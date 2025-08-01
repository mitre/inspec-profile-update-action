control 'SV-207521' do
  title 'The VMM must generate audit records when concurrent logons from different workstations occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records when concurrent logons from different workstations occur.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records when concurrent logons from different workstations occur.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7778r365967_chk'
  tag severity: 'medium'
  tag gid: 'V-207521'
  tag rid: 'SV-207521r381481_rule'
  tag stig_id: 'SRG-OS-000473-VMM-001930'
  tag gtitle: 'SRG-OS-000473'
  tag fix_id: 'F-7778r365968_fix'
  tag 'documentable'
  tag legacy: ['SV-71603', 'V-57343']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
