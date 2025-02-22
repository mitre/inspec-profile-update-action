control 'SV-222967' do
  title 'Keystore file must be protected.'
  desc 'Keystore file contains authentication information used to access application data and data resources. Access to the file must be protected.

The default location is in the .keystore file stored in the home folder of the user account used to run Tomcat although some administrators may choose to locate the file elsewhere. The location will also be specified in the server.xml file.'
  desc 'check', 'Identify the location of the .keystore file. Refer to system documentation or review the server.xml file for a specified .keystore file location.

From the Tomcat server console run the following command to check the server.xml file:

sudo grep -i keystorefile $CATALINA_BASE/conf/server.xml

Extract the location of the file from the output. 

Example:
[keystorefile=/opt/tomcat/conf/<filename.jks>]

sudo ls -la [keystorefile location]

If the file permissions are not set to 640 USER:root GROUP:tomcat, this is a finding.

If the keystore file is not stored within the tomcat folder path, i.e. [/opt/tomcat/], this is a finding.'
  desc 'fix', 'Run the following commands on the Tomcat server:

sudo chmod 640 [keystorefile]
sudo chown root [keystorefile]
sudo chgrp tomcat [keystorefile]

Store the keystore file in a secured folder within the Tomcat folder path.'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24639r426345_chk'
  tag severity: 'medium'
  tag gid: 'V-222967'
  tag rid: 'SV-222967r615938_rule'
  tag stig_id: 'TCAT-AS-000710'
  tag gtitle: 'SRG-APP-000176-AS-000125'
  tag fix_id: 'F-24628r426346_fix'
  tag 'documentable'
  tag legacy: ['SV-111459', 'V-102517']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
