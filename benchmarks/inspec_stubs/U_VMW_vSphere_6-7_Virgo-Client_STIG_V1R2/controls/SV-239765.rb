control 'SV-239765' do
  title 'vSphere Client must be configured to show error pages with minimal information.'
  desc 'Web servers will often display error messages to client users, displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. 

This information could be used by an attacker to blueprint what type of attacks might be successful. Therefore, vSphere Client must be configured to not show server version information in error messages.'
  desc 'check', %q(At the command prompt, execute the following command:

# xmllint --format --xpath '/Server/Service/Connector/@server' /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

server="Anonymous" server="Anonymous"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml.

Configure each <Connector> node with the following:

server="Anonymous"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Virgo-Client'
  tag check_id: 'C-42998r679520_chk'
  tag severity: 'medium'
  tag gid: 'V-239765'
  tag rid: 'SV-239765r879655_rule'
  tag stig_id: 'VCFL-67-000024'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-42957r679521_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
