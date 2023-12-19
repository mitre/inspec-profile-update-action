control 'SV-29486' do
  title 'Event log sizes do not meet minimum requirements.'
  desc 'Inadequate log size will cause the log to fill up quickly and require frequent clearing by administrative personnel.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Event Log -> Settings for Event Logs.

If the value for “Maximum application log size” is not set to a minimum of “16384 kilobytes”, then this is a finding.

If the value for “Maximum security log size” is not set to a minimum of “81920 kilobytes”, then this is a finding.

If the value for “Maximum system log size” is not set to a minimum of “16384 kilobytes”, then this is a finding.

 
Documentable Explanation: If the machine is configured to write an event log directly to an audit server, the “Maximum log size” for that log does not have to conform to the requirements above. This should be documented with the IAO.
 
 
Note:  Microsoft recommends that the combined size of all the event logs (including DNS logs, Directory Services logs, and Replication logs on Servers or Domain Controllers) should not exceed 300 megabytes.  Exceeding the recommended value can impact performance.'
  desc 'fix', 'Configure the system to have the required minimum Event log sizes.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-509r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1118'
  tag rid: 'SV-29486r1_rule'
  tag gtitle: 'Event Log Sizes'
  tag fix_id: 'F-5808r1_fix'
  tag potential_impacts: 'Microsoft recommends that the combined size of all the event logs (including DNS logs, Directory Services logs, and Replication logs on Servers or Domain Controllers) should not exceed 300 megabytes.  Exceeding the recommended value can impact performance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECRR-1'
end
