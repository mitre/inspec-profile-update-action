control 'SV-235983' do
  title 'Oracle WebLogic must separate hosted application functionality from Oracle WebLogic management functionality.'
  desc 'Application server management functionality includes functions necessary to administer the application server and requires privileged access via one of the accounts assigned to a management role. 

The separation of application server administration functionality from hosted application functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, network addresses, network ports, or combinations of these methods, as appropriate.'
  desc 'check', "1. Access AC 
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. A single server in the list will be named 'Admin Server' and this is the server which hosts AS management functionality, such as the AdminConsole application
4. All remaining servers in the list are 'Managed Servers' and these are the individual or clustered servers which will host the actual applications
5. Ensure no applications are deployed on the Admin server, rather, only on the Managed servers

If any applications are deployed on the Admin server, this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. A single server in the list will be named 'Admin Server' and this is the server which hosts AS management functionality, such as the AdminConsole application
4. All remaining servers in the list are 'Managed Servers' and these are the individual or clustered servers which will host the actual applications
5. Utilize 'Change Center' to create a new change session
6. Undeploy all applications that are not used for AS management from the Admin server, and redeploy onto the Managed servers
7. This can be done from 'Deployments' tab -> 'Targets' tab; select each application which must be redeployed , deselect 'Admin Server' and select one or more of the Managed servers
8. Click 'Save' and restart servers if necessary"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39202r628725_chk'
  tag severity: 'medium'
  tag gid: 'V-235983'
  tag rid: 'SV-235983r628727_rule'
  tag stig_id: 'WBLC-08-000222'
  tag gtitle: 'SRG-APP-000211-AS-000146'
  tag fix_id: 'F-39165r628726_fix'
  tag 'documentable'
  tag legacy: ['SV-70571', 'V-56317']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
