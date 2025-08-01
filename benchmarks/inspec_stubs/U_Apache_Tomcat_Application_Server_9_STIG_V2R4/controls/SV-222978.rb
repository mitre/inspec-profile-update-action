control 'SV-222978' do
  title 'Tomcat server version must not be sent with warnings and errors.'
  desc 'A first order of attack is to identify vulnerable servers and services. Removing version information that would otherwise be provided when a client requests version data or receives an error message can limit automated attack attempts. Remove or replace the version string from HTTP error messages by repacking $CATALINA_HOME/server/lib/catalina.jar with an updated ServerInfo.properties file. This will modify the server information that is provided in error and warning responses.'
  desc 'check', 'From the Tomcat server, cd to the $CATALINA_HOME/bin folder.  Run the version.sh command and identify the following information that is provided:
Server version:
Server built:
Server number:

EXAMPLE:
Server version: Apache Tomcat
Server built: July 4 2019 14:20:06 UTC
Server number: 9.0.22.0

If additional version information is required, refer to the Apache Tomcat version 9 change log on the Apache Tomcat website for historical version information. Google "Apache Tomcat 9 changelog".

If server.info="Apache Tomcat" or server.number=the valid Tomcat version, this is a finding.'
  desc 'fix', 'From the Tomcat server, cd to the $CATALINA_HOME/lib folder. As a privileged user run the following case sensitive command:

sudo jar -xf catalina.jar org/apache/catalina/util/ServerInfo.properties

Edit the ServerInfo.properties file.
sudo nano org/apache/catalina/util/ServerInfo.properties

Change server.info and server.number to read:
server.info=<Enter Some Random Name or Value>
server.number=<Enter Some Random number>

EXAMPLE:
server.info="Standard Server"
server.number=1.0.2.11

Save the ServerInfo.properties file.

Run the following command to update the catalina.jar file:
sudo jar -uf catalina.jar org/apache/catalina/util/ServerInfo.properties

Restart the Tomcat server:
sudo systemctl restart tomcat
sudo rm -rf $CATALINA_HOME/lib/org'
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24650r426378_chk'
  tag severity: 'low'
  tag gid: 'V-222978'
  tag rid: 'SV-222978r615938_rule'
  tag stig_id: 'TCAT-AS-000950'
  tag gtitle: 'SRG-APP-000267-AS-000170'
  tag fix_id: 'F-24639r426379_fix'
  tag 'documentable'
  tag legacy: ['SV-111479', 'V-102539']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
