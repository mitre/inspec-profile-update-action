control 'SV-207512' do
  title 'The VMM must generate audit records when successful/unsuccessful attempts to modify privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records when successful/unsuccessful attempts to modify privileges occur.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records when successful/unsuccessful attempts to modify privileges occur.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7769r365940_chk'
  tag severity: 'medium'
  tag gid: 'V-207512'
  tag rid: 'SV-207512r381448_rule'
  tag stig_id: 'SRG-OS-000462-VMM-001840'
  tag gtitle: 'SRG-OS-000462'
  tag fix_id: 'F-7769r365941_fix'
  tag 'documentable'
  tag legacy: ['SV-71585', 'V-57325']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
