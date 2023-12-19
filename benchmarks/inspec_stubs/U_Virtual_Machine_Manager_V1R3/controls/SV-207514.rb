control 'SV-207514' do
  title 'The VMM must generate audit records when successful/unsuccessful attempts to modify security levels occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records when successful/unsuccessful attempts to modify security levels occur.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records when successful/unsuccessful attempts to modify security levels occur.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7771r365946_chk'
  tag severity: 'medium'
  tag gid: 'V-207514'
  tag rid: 'SV-207514r381454_rule'
  tag stig_id: 'SRG-OS-000464-VMM-001860'
  tag gtitle: 'SRG-OS-000464'
  tag fix_id: 'F-7771r365947_fix'
  tag 'documentable'
  tag legacy: ['V-57329', 'SV-71589']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
