control 'SV-106399' do
  title 'The ISEC7 EMM Suite must remove any unnecessaryusers or groups that have permissions to the server.xml file in Apache Tomcat.'
  desc 'Tomcat uses a port (defaults to 8005) as a shutdown port. Someone could Telnet to the machine using this port and send the default command SHUTDOWN. Tomcat and all web apps would shut down in that case, which is a denial of service attack and would cause an unwanted service interruption.'
  desc 'check', 'Verify unnecessaryusers or groups that have permissions to the Server.xml file in Apache Tomcat have been removed.

Browse to ProgramFiles\\Isec7 EMM Suite\\Tomcat\\Conf and select Server.xml
Right click and select Properties.
Select the security tab and verify no unnecessaryaccount or groups have been granted permissions to the file.
Verify no unnecessaryusers or groups have permissions to the file.

If unnecessaryusers or groups that have permissions to the Server.xml file in Apache Tomcat have not been removed, this is a finding.'
  desc 'fix', 'Log in to the ISEC7 EMM Suite server.
Browse to ProgramFiles\\Isec7 EMM Suite\\Tomcat\\Conf and select Server.xml
Right click and select Properties.
Select the security tab and remove unnecessaryaccounts or groups that have been granted permissions to the Server.xml file.'
  impact 0.5
  ref 'DPMS Target ISEC7 EMM Suite v6.x'
  tag check_id: 'C-96131r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97295'
  tag rid: 'SV-106399r1_rule'
  tag stig_id: 'ISEC-06-551310'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-102975r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
