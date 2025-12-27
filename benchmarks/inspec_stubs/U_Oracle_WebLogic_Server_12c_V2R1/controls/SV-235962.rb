control 'SV-235962' do
  title 'Oracle WebLogic must prohibit or restrict the use of unauthorized functions, ports, protocols, and/or services.'
  desc 'Application servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed to be unnecessary or too insecure to run on a production system. The application server must provide the capability to disable or deactivate network-related services that are deemed to be non-essential to the server mission, for example, disabling a protocol or feature that opens a listening port that is prohibited by DoD ports and protocols. For a list of approved ports and protocols reference the DoD ports and protocols web site at https://cyber.mil/ppsm.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Monitoring' -> 'Port Usage' 
3. In the results table, ensure values in the 'Port in Use' column match approved ports
4. In the results table, ensure values in the 'Protocol' column match approved protocols

If any ports listed in the 'Port in Use' column is an unauthorized port or any protocols listed in the 'Protocol' column is an unauthorized protocol, this is a finding."
  desc 'fix', "1. Access AC
2. To change port or protocol values, from 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs modification
4. Utilize 'Change Center' to create a new change session 
5. To modify port assignment, from 'Configuration' tab -> 'General' tab, reassign the port for this server by changing the 'SSL Listen Port' field and click 'Save'
6. To modify protocol configuration, select 'Protocols' tab 
7. Use the subtabs 'HTTP', 'jCOM' and 'IIOP' to configure these protocols
8. Use the 'Channels' subtab to create/modify channels which configure other protocols
9. Repeat steps 3-8 for all servers requiring modification
10. Review the 'Port Usage' table in EM again to ensure port has been reassigned"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39181r628662_chk'
  tag severity: 'medium'
  tag gid: 'V-235962'
  tag rid: 'SV-235962r672376_rule'
  tag stig_id: 'WBLC-03-000128'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-39144r628663_fix'
  tag 'documentable'
  tag legacy: ['SV-70527', 'V-56273']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
