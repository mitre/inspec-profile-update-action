control 'SV-224789' do
  title 'The Apache Tomcat shutdown port must be disabled.'
  desc 'Tomcat uses a port (defaults to 8005) as a shutdown port. Someone could Telnet to the machine using this port and send the default command SHUTDOWN. Tomcat and all web apps would shut down in that case, which is a denial of service attack and would cause an unwanted service interruption.'
  desc 'check', 'Verify the shutdown port is disabled.

Log in to the EMM Suite server.
Browse to Program Files\\Isec7 EMM Suite\\Tomcat\\Conf
Open the server.xml with Notepad.exe
Select Edit >> Find and search for Shutdown.
Verify that the shutdown port has been disabled with below entry:

shutdown="-1"

If the shutdown port has not been disabled, this is a finding.'
  desc 'fix', 'Log in to the EMM Suite server.
Browse to Program Files\\Isec7 EMM Suite\\Tomcat\\Conf
Open the server.xml with Notepad.exe
Select Edit >> Find and search for Shutdown.
Change the shutdown to -1

example:  shutdown=-1

Save the file and restart the Isec7 EMM Suite Web service with the services.msc'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26480r461623_chk'
  tag severity: 'medium'
  tag gid: 'V-224789'
  tag rid: 'SV-224789r505933_rule'
  tag stig_id: 'ISEC-06-551300'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-26468r461624_fix'
  tag 'documentable'
  tag legacy: ['SV-106397', 'V-97293']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
