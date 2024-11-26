control 'SV-203760' do
  title 'The operating system must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3885r375401_chk'
  tag severity: 'medium'
  tag gid: 'V-203760'
  tag rid: 'SV-203760r380335_rule'
  tag stig_id: 'SRG-OS-000461-GPOS-00205'
  tag gtitle: 'SRG-OS-000461'
  tag fix_id: 'F-3885r375402_fix'
  tag 'documentable'
  tag legacy: ['V-56711', 'SV-70971']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
