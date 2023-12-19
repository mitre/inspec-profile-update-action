control 'SV-207513' do
  title 'The VMM must generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records when successful/unsuccessful attempts to modify security objects occur.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7770r365943_chk'
  tag severity: 'medium'
  tag gid: 'V-207513'
  tag rid: 'SV-207513r381451_rule'
  tag stig_id: 'SRG-OS-000463-VMM-001850'
  tag gtitle: 'SRG-OS-000463'
  tag fix_id: 'F-7770r365944_fix'
  tag 'documentable'
  tag legacy: ['V-57327', 'SV-71587']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
