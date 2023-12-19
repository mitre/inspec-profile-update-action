control 'SV-1095' do
  title 'Anonymous access to the event logs is not restricted.'
  desc 'By default, the Windows event logs may be viewed over the network by an anonymous user.  This method of access over the network is communicating through the Server service which has SYSTEM access to the actual log files.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Event Logs -> Settings for Event Logs.

If the value for “Prevent local guests group from accessing application log” is not set to “Enabled”, then this is a finding.

If the value for “Prevent local guests group from accessing security log” is not set to “Enabled”, then this is a finding.

If the value for “Prevent local guests group from accessing system log” is not set to “Enabled”, then this is a finding.'
  desc 'fix', 'Configure the system to prevent guest access to the Event logs.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-72r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1095'
  tag rid: 'SV-1095r1_rule'
  tag gtitle: 'Restrict Event Log Access over the Network'
  tag fix_id: 'F-84r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTP-1'
end
