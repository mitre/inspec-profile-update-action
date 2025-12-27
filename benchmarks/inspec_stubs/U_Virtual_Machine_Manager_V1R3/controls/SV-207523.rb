control 'SV-207523' do
  title 'The VMM must generate audit records for all direct access to the VMM.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records for all direct access to the VMM.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records for all direct access to the VMM.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7780r365973_chk'
  tag severity: 'medium'
  tag gid: 'V-207523'
  tag rid: 'SV-207523r381487_rule'
  tag stig_id: 'SRG-OS-000475-VMM-001950'
  tag gtitle: 'SRG-OS-000475'
  tag fix_id: 'F-7780r365974_fix'
  tag 'documentable'
  tag legacy: ['V-57347', 'SV-71607']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
