control 'SV-233920' do
  title 'In the event of a system failure, the Infoblox system must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. 

Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'By default, all system events are logged to the local SYSLOG and stored on the Infoblox appliance. To ensure log data is preserved in the event of system failure, an external log server must be configured. Verify that external logging is operational and messages from the Audit log are also forwarded to the remote log system. 

1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration. 
2. Select the "Monitoring" tab. 
3. Validate that "Log to External Syslog Servers" is enabled and an External Syslog Server must be configured. 
4. Validate "Copy Audit Log Message to Syslog" is enabled. 
5. When complete, click "Cancel" to exit the "Properties" screen. 

If both "Log to External Syslog Servers" and "Copy Audit Log Message to Syslog" are not enabled, this is a finding.'
  desc 'fix', '1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration.  
2. Select the "Monitoring" tab. 
3. Enable "Log to External Syslog Server" and configure at least one External Syslog Server.  
4. Enable the option "Copy Audit Log Message to Syslog".  
5. Click "Save & Close" to save the changes and exit the "Properties" screen.  
6. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37105r611280_chk'
  tag severity: 'medium'
  tag gid: 'V-233920'
  tag rid: 'SV-233920r621666_rule'
  tag stig_id: 'IDNS-8X-700015'
  tag gtitle: 'SRG-APP-000226-DNS-000032'
  tag fix_id: 'F-37070r611281_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
