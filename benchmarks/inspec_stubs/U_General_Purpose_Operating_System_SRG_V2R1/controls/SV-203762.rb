control 'SV-203762' do
  title 'The operating system must generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to modify security objects occur. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3887r375407_chk'
  tag severity: 'medium'
  tag gid: 'V-203762'
  tag rid: 'SV-203762r381451_rule'
  tag stig_id: 'SRG-OS-000463-GPOS-00207'
  tag gtitle: 'SRG-OS-000463'
  tag fix_id: 'F-3887r375408_fix'
  tag 'documentable'
  tag legacy: ['SV-70903', 'V-56643']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
