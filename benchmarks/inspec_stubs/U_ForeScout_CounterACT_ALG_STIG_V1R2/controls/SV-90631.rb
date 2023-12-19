control 'SV-90631' do
  title 'CounterACT must off-load audit records onto a centralized log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify CounterACT off-loads audit records onto a centralized log server. 

1. Connect to CounterACT’s Admin Console and log in.
2. Go to Tools >> Options >> Plugins >> Syslog.
3. Verify a Syslog server is configured in the "Send To" tab.
4. On the Events Filtering Tab, ensure all radio buttons associated with NAC Events, Threat Protection, System Logs, User Operations, and Operating System messages are selected. 

If CounterACT does not off-load audit records onto a centralized log server, this is a finding.'
  desc 'fix', 'Configure CounterACT to off-load audit records onto a centralized log server. 

1. Connect to CounterACT’s Admin Console and log in.
2. Go to Tools >> Options >> Plugins >> Syslog.
3. Ensure a Syslog server is configured in the "Send To" tab.
4. On the Events Filtering Tab, ensure all radio buttons associated with NAC Events, Threat Protection, System Logs, User Operations, and Operating System messages are selected.
5. Select "OK". (Select "Apply" if changes were made.)'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT ALG'
  tag check_id: 'C-75625r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75943'
  tag rid: 'SV-90631r1_rule'
  tag stig_id: 'CACT-AG-000010'
  tag gtitle: 'SRG-NET-000334-ALG-000050'
  tag fix_id: 'F-82581r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
