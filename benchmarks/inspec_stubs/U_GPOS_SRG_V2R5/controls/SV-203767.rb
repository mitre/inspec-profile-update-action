control 'SV-203767' do
  title 'The operating system must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful logon attempts occur. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful logon attempts occur.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3892r375422_chk'
  tag severity: 'medium'
  tag gid: 'V-203767'
  tag rid: 'SV-203767r381472_rule'
  tag stig_id: 'SRG-OS-000470-GPOS-00214'
  tag gtitle: 'SRG-OS-000470'
  tag fix_id: 'F-3892r375423_fix'
  tag 'documentable'
  tag legacy: ['V-56619', 'SV-70879']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
