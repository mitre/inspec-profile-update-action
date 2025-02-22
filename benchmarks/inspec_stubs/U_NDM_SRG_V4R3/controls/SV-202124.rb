control 'SV-202124' do
  title 'The network device must generate audit records for privileged activities or other system-level access.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records for privileged activities or other system-level access.

If the network device does not generate audit records for privileged activities or other system-level access, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records for privileged activities or other system-level access.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2250r382052_chk'
  tag severity: 'medium'
  tag gid: 'V-202124'
  tag rid: 'SV-202124r879875_rule'
  tag stig_id: 'SRG-APP-000504-NDM-000321'
  tag gtitle: 'SRG-APP-000504'
  tag fix_id: 'F-2251r382053_fix'
  tag 'documentable'
  tag legacy: ['SV-69525', 'V-55279']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
