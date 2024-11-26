control 'SV-207525' do
  title 'The VMM must generate audit records for all module load, unload, and restart actions, and also for all program and guest VM initiations.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records for all module load, unload, and restart actions, and also for all program and guest VM initiations.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records for all module load, unload, and restart actions, and also for all program and guest VM initiations.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7782r365979_chk'
  tag severity: 'medium'
  tag gid: 'V-207525'
  tag rid: 'SV-207525r381493_rule'
  tag stig_id: 'SRG-OS-000477-VMM-001970'
  tag gtitle: 'SRG-OS-000477'
  tag fix_id: 'F-7782r365980_fix'
  tag 'documentable'
  tag legacy: ['V-57351', 'SV-71611']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
