control 'SV-30015' do
  title 'The Hardware Management Console Event log must be active.'
  desc 'The Hardware Management Console controls the operation and availability of the Central Processor Complex (CPC). Failure to create and maintain the Hardware Management Console Event log could result in the lack of monitoring and accountability of CPC control activity.'
  desc 'check', 'Verify on the Hardware Management Console that the Event log is in use. 

This is done by selecting the View Console Events panel under Console Actions.
From this panel you can display:

Console Information on EC Changes
Console Service History displays HMC Problems
Console Tasks Displays Last 2000 tasks performed on console
View Licenses View LIC (Licensed Internal Code)
View Security Logs  tracks an object’s operational state, status, or settings change or involves user access to tasks, actions, and objects.

If no Event log exists, this is a FINDING.

If the Event log exists and is not collecting data, this is a FINDING.'
  desc 'fix', 'The System Administrator will activate the Hardware Management Console Event log and ensure that all tracking parameters are set.

This is done by selecting the View Console Events panel under Console Actions.
From this panel you can display:

Console Information on EC Changes
Console Service History displays HMC Problems
Console Tasks Displays Last 2000 tasks performed on console
View Licenses View LIC (Licensed Internal Code)
View Security Logs  tracks an object’s operational state, status, or settings change or involves user access to tasks, actions, and objects.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-2924r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24352'
  tag rid: 'SV-30015r2_rule'
  tag stig_id: 'HMC0070'
  tag gtitle: 'HMC0070'
  tag fix_id: 'F-2353r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECAT-1, ECAT-2'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
