control 'SV-29486' do
  title 'Event log sizes do not meet minimum requirements.'
  desc 'Inadequate log size will cause the log to fill up quickly and require frequent clearing by administrative personnel.'
  desc 'fix', 'Configure the system to have the required minimum Event log sizes.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-1118'
  tag rid: 'SV-29486r1_rule'
  tag gtitle: 'Event Log Sizes'
  tag fix_id: 'F-5808r1_fix'
  tag potential_impacts: 'Microsoft recommends that the combined size of all the event logs (including DNS logs, Directory Services logs, and Replication logs on Servers or Domain Controllers) should not exceed 300 megabytes.  Exceeding the recommended value can impact performance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECRR-1'
end
