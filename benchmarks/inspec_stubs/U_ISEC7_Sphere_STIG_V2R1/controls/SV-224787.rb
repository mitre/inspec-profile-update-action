control 'SV-224787' do
  title 'The version number of Apache Tomcat must be removed from the CATALINA_HOME/lib/catalina.jar file.'
  desc 'If the version number of Apache Tomcat were visible to an intruder, they could use that information to search for known vulnerabilities of the app. Removal of unneeded or non-secure functions, ports, protocols, and services mitigate the risk of unauthorized connection of devices, unauthorized transfer of information, or other exploitation of these resources.

The organization must perform a periodic scan/review of the application (as required by CCI-000384) and disable functions, ports, protocols, and services deemed to be unneeded or non-secure.'
  desc 'check', 'Verify the version number of Apache Tomcat has been removed from the CATALINA_HOME/lib/catalina.jar file.

Open a CMD prompt.
cd <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\lib
Copy to desktop and rename catalina.jar to catalina.zip
Open catalina.zip and drill down to org/apache/catalina/util/ServerInfo.properties
Open  ‘ServerInfo.properties’ with WordPad.
Confirm the server version information has been removed.
…
server.info=Apache Tomcat
server.number=
server.built=

If the version number of Apache Tomcat has not been removed from the CATALINA_HOME/lib/catalina.jar file, this is a finding.'
  desc 'fix', 'Remove the version string from HTTP error pages by unpacking ServerInfo.properties from CATALINA_HOME\\lib\\catalina.jar and updating the server version information: 

Open a CMD prompt.
cd <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\lib
Copy to desktop and rename catalina.jar to catalina.zip
Open catalina.zip and drill down to org/apache/catalina/util/ServerInfo.properties
Open  ‘ServerInfo.properties’ with WordPad.
Edit the server version information and save.
…
server.info=Apache Tomcat
server.number=
server.built=

Save file, rename to catalina.jar, and copy back to directory, replacing existing file.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26478r461617_chk'
  tag severity: 'medium'
  tag gid: 'V-224787'
  tag rid: 'SV-224787r505933_rule'
  tag stig_id: 'ISEC-06-551100'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-26466r461618_fix'
  tag 'documentable'
  tag legacy: ['V-97289', 'SV-106393']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
