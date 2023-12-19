control 'SV-90877' do
  title 'CounterACT must off-load audit records onto a centralized log server in real time.'
  desc 'Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

Off-loading is a common process in information systems with limited audit storage capacity. The audit storage on the ALG is used only in a transitory fashion until the system can communicate with the centralized log server designated for storing the audit records, at which point the information is transferred. However, DoD requires that the log be transferred in real time which indicates that the time from event detection to off-loading is seconds or less.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify CounterACT off-loads audit records onto a centralized log server in real time. 

1. Connect to CounterACT’s Admin Console and log in.
2. Go to Tools >> Options >> Plugins >> Syslog.
3. Verify a Syslog server is configured in the "Send To" tab.
4. On the Events Filtering Tab, Verify all radio buttons associated with NAC Events, Threat Protection, System Logs, User Operations, and Operating systems messages are selected. 

If CounterACT does not off-load onto a centralized log server in real time, this is a finding.'
  desc 'fix', 'Configure CounterACT to off-load onto a centralized log server in real time. 

1. Connect to CounterACT’s Admin Console and log in.
2. Go to Tools >> Options >> Plugins >> Syslog.
3. Ensure a Syslog server is configured in the "Send To" tab.
4. On the Events Filtering Tab, ensure all radio buttons associated with NAC Events, Threat Protection, System Logs, User Operations, and Operating systems messages are selected.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT ALG'
  tag check_id: 'C-75875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76189'
  tag rid: 'SV-90877r1_rule'
  tag stig_id: 'CACT-AG-000014'
  tag gtitle: 'SRG-NET-000511-ALG-000051'
  tag fix_id: 'F-82827r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
