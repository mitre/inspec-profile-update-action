control 'SV-207524' do
  title 'The VMM must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records for all account creations, modifications, disabling, and termination events.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records for all account creations, modifications, disabling, and termination events.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7781r365976_chk'
  tag severity: 'medium'
  tag gid: 'V-207524'
  tag rid: 'SV-207524r381490_rule'
  tag stig_id: 'SRG-OS-000476-VMM-001960'
  tag gtitle: 'SRG-OS-000476'
  tag fix_id: 'F-7781r365977_fix'
  tag 'documentable'
  tag legacy: ['V-57349', 'SV-71609']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
