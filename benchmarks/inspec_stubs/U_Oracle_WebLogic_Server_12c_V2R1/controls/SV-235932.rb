control 'SV-235932' do
  title 'Oracle WebLogic must support the capability to disable network protocols deemed by the organization to be non-secure except for explicitly identified components in support of specific operational requirements.'
  desc 'Some networking protocols may not meet organizational security requirements to protect data and components. 

Application servers natively host a number of various features such as management interfaces, httpd servers, and message queues. These features all run on TCPIP ports. This creates the potential that the vendor may choose to utilize port numbers or network services that have been deemed unusable by the organization. The application server must have the capability to both reconfigure and disable the assigned ports without adversely impacting application server operation capabilities. For a list of approved ports and protocols, reference the DoD ports and protocols web site at https://cyber.mil/ppsm.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Monitoring' -> 'Port Usage' 
3. In the results table, ensure values in the 'Port in Use' column match approved ports
4. In the results table, ensure values in the 'Protocol' column match approved protocols

If ports or protocols are in use that the organization deems nonsecure, this is a finding."
  desc 'fix', "1. Access AC
2. To change port or protocol values, from 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs modification
4. Utilize 'Change Center' to create a new change session 
5. To modify port assignment, from 'Configuration' tab -> 'General' tab, reassign the port for this server by changing the 'SSL Listen Port' field and click 'Save'
6. To modify protocol configuration, select 'Protocols' tab 
7. Use the subtabs 'HTTP', 'jCOM', and 'IIOP' to configure these protocols
8. Use the 'Channels' subtab to create/modify channels which configure other protocols
9. Repeat steps 3-8 for all servers requiring modification
10. Review the 'Port Usage' table in EM again to ensure port has been reassigned"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39151r628572_chk'
  tag severity: 'medium'
  tag gid: 'V-235932'
  tag rid: 'SV-235932r672375_rule'
  tag stig_id: 'WBLC-01-000014'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-39114r628573_fix'
  tag 'documentable'
  tag legacy: ['SV-70467', 'V-56213']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
