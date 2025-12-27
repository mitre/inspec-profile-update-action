control 'SV-16946' do
  title 'Event log sizes do not meet minimum requirements.'
  desc 'Inadequate log size will cause the log to fill up quickly and require frequent clearing by administrative personnel.'
  desc 'fix', 'Configure the following policy values as listed below:

Computer Configuration -> Administrative Templates -> Windows Components -> Event Log Service -> 

Application -> “Maximum Log Size (KB)” will be set to “Enabled:32768”
Security -> “Maximum Log Size (KB)” will be set to “Enabled:81920”
Setup -> “Maximum Log Size (KB)” will be set to “Enabled:32768”
System -> “Maximum Log Size (KB)” will be set to “Enabled:32768”'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1118'
  tag rid: 'SV-16946r1_rule'
  tag gtitle: 'Event Log Sizes'
  tag fix_id: 'F-16018r1_fix'
  tag potential_impacts: 'Microsoft recommends that the combined size of all the event logs (including DNS logs, Directory Services logs, and Replication logs on Servers or Domain Controllers) should not exceed 300 megabytes.  Exceeding the recommended value can impact performance.'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
