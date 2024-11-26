control 'SV-75331' do
  title 'The Arista Multilayer Switch must generate audit records for privileged activities or other system-level access.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records for privileged activities or other system-level access. 

If the network device does not generate audit records for privileged activities or other system-level access, this is a finding.

Verify logging is configured to audit full-text commands.

Execute a "show logging" command and review the logs to verify the full text of commands is included.'
  desc 'fix', 'Configure the network device to generate audit records for privileged activities or other system-level access.

aaa accounting commands all default start-stop
aaa accounting exec default start-stop
aaa accounting system default start-stop'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61821r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60873'
  tag rid: 'SV-75331r1_rule'
  tag stig_id: 'AMLS-NM-000360'
  tag gtitle: 'SRG-APP-000504-NDM-000321'
  tag fix_id: 'F-66585r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
