control 'SV-207519' do
  title 'The VMM must generate audit records for privileged activities or other system-level access.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records for privileged activities or other system-level access.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records for privileged activities or other system-level access.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7776r365961_chk'
  tag severity: 'medium'
  tag gid: 'V-207519'
  tag rid: 'SV-207519r381475_rule'
  tag stig_id: 'SRG-OS-000471-VMM-001910'
  tag gtitle: 'SRG-OS-000471'
  tag fix_id: 'F-7776r365962_fix'
  tag 'documentable'
  tag legacy: ['V-57339', 'SV-71599']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
