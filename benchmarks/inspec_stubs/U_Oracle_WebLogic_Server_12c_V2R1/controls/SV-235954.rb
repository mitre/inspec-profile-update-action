control 'SV-235954' do
  title 'Oracle WebLogic must use internal system clocks to generate time stamps for audit records.'
  desc 'Without the use of an approved and synchronized time source, configured on the systems, events cannot be accurately correlated and analyzed to determine what is transpiring within the application server. 

If an event has been triggered on the network, and the application server is not configured with the correct time, the event may be seen as insignificant, when in reality the events are related and may have a larger impact across the network. Synchronization of system clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. Determining the correct time a particular event occurred on a system, via time stamps, is critical when conducting forensic analysis and investigating system events. 
Application servers must utilize the internal system clock when generating time stamps and audit records.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Security Provider Configuration' 
3. Beneath 'Audit Service' section, click 'Configure' button 
4. Ensure the 'Timezone Settings' radio button is set to 'UTC' so audit logs will be time stamped in Coordinated Universal Time regardless of the time zone of the underlying physical or virtual machine 
5. The time stamp will be recorded according to the operating system's set time

If the 'Timezone Settings' radio button is not set to 'UTC', this is a finding."
  desc 'fix', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Security Provider Configuration' 
3. Beneath 'Audit Service' section, click 'Configure' button 
4. Set the 'Timezone Settings' radio button to 'UTC' so audit logs will be time stamped in Coordinated Universal Time regardless of the time zone of the underlying physical or virtual machine 
5. The time stamp will be recorded according to the operating system's set time 
6. Click 'Apply' and restart the servers in the WebLogic domain"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39173r628638_chk'
  tag severity: 'low'
  tag gid: 'V-235954'
  tag rid: 'SV-235954r628640_rule'
  tag stig_id: 'WBLC-02-000093'
  tag gtitle: 'SRG-APP-000116-AS-000076'
  tag fix_id: 'F-39136r628639_fix'
  tag 'documentable'
  tag legacy: ['SV-70511', 'V-56257']
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
