control 'SV-203759' do
  title 'The operating system must generate audit records when successful/unsuccessful attempts to access security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to access security objects occur. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to access security objects occur.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3884r375398_chk'
  tag severity: 'medium'
  tag gid: 'V-203759'
  tag rid: 'SV-203759r380329_rule'
  tag stig_id: 'SRG-OS-000458-GPOS-00203'
  tag gtitle: 'SRG-OS-000458'
  tag fix_id: 'F-3884r375399_fix'
  tag 'documentable'
  tag legacy: ['SV-70973', 'V-56713']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
