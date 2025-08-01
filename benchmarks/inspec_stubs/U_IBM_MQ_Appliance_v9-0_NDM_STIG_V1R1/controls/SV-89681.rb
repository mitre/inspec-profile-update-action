control 'SV-89681' do
  title 'Applications used for nonlocal maintenance sessions using the MQ Appliance WebGUI must implement cryptographic mechanisms to protect the confidentiality and integrity of nonlocal maintenance and diagnostic communications.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to manipulation, potentially allowing alteration and hijacking of maintenance sessions.

'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Display the SSL Server Profile associated with the WebGUI (CLI). Enter: 
co 
show web-mgmt 

Verify the following: 
An ssl-server is associated with the WebGUI. 
[Note the name of the ssl-server.] 

List parameters of the SSL Server (CLI). Enter: 
co 
crypto 
ssl-server <ssl-server name> 
show 

Verify the following: 
protocols TLSv1d2

If TLS protocol is not configured for use with the ssl-server, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. 

Display the SSL Server Profile associated with the WebGUI (CLI). Enter: 
co 
show web-mgmt 

[Note the name of the ssl-server.] 

Define the cache parameters of the SSL Server (CLI). Enter: 
co 
crypto 
ssl-server <ssl-server name> 
protocols TLSv1d2 
exit 
exit 
write mem 
y'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74859r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75007'
  tag rid: 'SV-89681r1_rule'
  tag stig_id: 'MQMH-ND-001260'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-81623r1_fix'
  tag satisfies: ['SRG-APP-000411-NDM-000330', 'SRG-APP-000412-NDM-000331']
  tag 'documentable'
  tag cci: ['CCI-002890', 'CCI-003123']
  tag nist: ['MA-4 (6)', 'MA-4 (6)']
end
