control 'SV-207520' do
  title 'The VMM must generate audit records showing starting and ending time for user access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records showing starting and ending time for user access to the system. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records showing starting and ending time for user access to the system.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7777r365964_chk'
  tag severity: 'medium'
  tag gid: 'V-207520'
  tag rid: 'SV-207520r381478_rule'
  tag stig_id: 'SRG-OS-000472-VMM-001920'
  tag gtitle: 'SRG-OS-000472'
  tag fix_id: 'F-7777r365965_fix'
  tag 'documentable'
  tag legacy: ['V-57341', 'SV-71601']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
