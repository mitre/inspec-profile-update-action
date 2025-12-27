control 'SV-207522' do
  title 'The VMM must generate audit records when successful/unsuccessful accesses to objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records when successful/unsuccessful accesses to objects occur.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records when successful/unsuccessful accesses to objects occur.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7779r365970_chk'
  tag severity: 'medium'
  tag gid: 'V-207522'
  tag rid: 'SV-207522r381484_rule'
  tag stig_id: 'SRG-OS-000474-VMM-001940'
  tag gtitle: 'SRG-OS-000474'
  tag fix_id: 'F-7779r365971_fix'
  tag 'documentable'
  tag legacy: ['V-57345', 'SV-71605']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
