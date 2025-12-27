control 'SV-207518' do
  title 'The VMM must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records when successful/unsuccessful logon attempts occur.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records when successful/unsuccessful logon attempts occur.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7775r365958_chk'
  tag severity: 'medium'
  tag gid: 'V-207518'
  tag rid: 'SV-207518r381472_rule'
  tag stig_id: 'SRG-OS-000470-VMM-001900'
  tag gtitle: 'SRG-OS-000470'
  tag fix_id: 'F-7775r365959_fix'
  tag 'documentable'
  tag legacy: ['V-57337', 'SV-71597']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
