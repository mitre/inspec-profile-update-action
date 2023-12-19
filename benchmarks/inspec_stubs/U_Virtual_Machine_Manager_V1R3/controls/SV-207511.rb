control 'SV-207511' do
  title 'The VMM must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the VMM (e.g., module or policy filter).'
  desc 'check', 'Verify the VMM generates audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7768r365937_chk'
  tag severity: 'medium'
  tag gid: 'V-207511'
  tag rid: 'SV-207511r380335_rule'
  tag stig_id: 'SRG-OS-000461-VMM-001830'
  tag gtitle: 'SRG-OS-000461'
  tag fix_id: 'F-7768r365938_fix'
  tag 'documentable'
  tag legacy: ['SV-71583', 'V-57323']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
