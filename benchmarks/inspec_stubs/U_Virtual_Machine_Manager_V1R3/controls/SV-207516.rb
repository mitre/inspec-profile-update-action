control 'SV-207516' do
  title 'The VMM must generate audit records when successful/unsuccessful attempts to delete security levels occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records when successful/unsuccessful attempts to delete security levels occur.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records when successful/unsuccessful attempts to delete security levels occur.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7773r365952_chk'
  tag severity: 'medium'
  tag gid: 'V-207516'
  tag rid: 'SV-207516r381463_rule'
  tag stig_id: 'SRG-OS-000467-VMM-001880'
  tag gtitle: 'SRG-OS-000467'
  tag fix_id: 'F-7773r365953_fix'
  tag 'documentable'
  tag legacy: ['V-57333', 'SV-71593']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
