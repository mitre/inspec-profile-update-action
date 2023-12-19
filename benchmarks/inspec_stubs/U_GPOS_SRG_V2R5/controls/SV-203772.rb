control 'SV-203772' do
  title 'The operating system must generate audit records when successful/unsuccessful accesses to objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful accesses to objects occur. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful accesses to objects occur.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3897r375707_chk'
  tag severity: 'medium'
  tag gid: 'V-203772'
  tag rid: 'SV-203772r381484_rule'
  tag stig_id: 'SRG-OS-000474-GPOS-00219'
  tag gtitle: 'SRG-OS-000474'
  tag fix_id: 'F-3897r375708_fix'
  tag 'documentable'
  tag legacy: ['V-56609', 'SV-70869']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
