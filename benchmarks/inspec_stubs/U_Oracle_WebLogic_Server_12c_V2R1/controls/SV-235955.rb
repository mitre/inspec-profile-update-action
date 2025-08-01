control 'SV-235955' do
  title 'Oracle WebLogic must synchronize with internal information system clocks which, in turn, are synchronized on an organization-defined frequency with an organization-defined authoritative time source.'
  desc 'Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events. 

Synchronization of system clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. To meet that requirement the organization will define an authoritative time source and frequency to which each system will synchronize its internal clock. 

Application servers must defer accurate timekeeping services to the operating system upon which the application server is installed.'
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
  tag check_id: 'C-39174r628641_chk'
  tag severity: 'low'
  tag gid: 'V-235955'
  tag rid: 'SV-235955r628643_rule'
  tag stig_id: 'WBLC-02-000094'
  tag gtitle: 'SRG-APP-000372-AS-000212'
  tag fix_id: 'F-39137r628642_fix'
  tag 'documentable'
  tag legacy: ['SV-70513', 'V-56259']
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end
