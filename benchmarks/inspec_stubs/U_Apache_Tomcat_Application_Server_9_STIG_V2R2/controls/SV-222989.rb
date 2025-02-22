control 'SV-222989' do
  title '$CATALINA_BASE/temp/ folder must be owned by tomcat user, group tomcat.'
  desc 'Tomcat file permissions must be restricted. The standard configuration is to have all Tomcat files owned by root with group Tomcat. While root has read/write privileges, group only has read permissions, and world has no permissions. The exceptions are the logs, temp, and work directories that are owned by the Tomcat user rather than root. This means that even if an attacker compromises the Tomcat process, they cannot change the Tomcat configuration, deploy new web applications, or modify existing web applications. The Tomcat process runs with a umask of 007 to maintain these permissions.

If operational needs require application administrators to be able to change application configurations, the group permissions can be modified to allow specific application admins the access they require with an ISSM risk acceptance.  Ownership may not change. The exposure of the system to high risk networks should always be taken into account.'
  desc 'check', 'Access the Tomcat server from the command line and execute the following OS command:

sudo find $CATALINA_BASE/temp -follow -maxdepth 0 \\(  ! -user tomcat -o ! -group tomcat \\) -ls

If ISSM risk acceptance specifies deviation from requirement based on operational/application needs, this is not a finding if the permissions are set in accordance with the risk acceptance.

If no folders are displayed, this is not a finding.

If results indicate the $CATALINA_BASE/temp folder ownership and group membership is not set to tomcat:tomcat, this is a finding.'
  desc 'fix', 'If operational/application requirements specify different file permissions, obtain ISSM risk acceptance and set permissions according to risk acceptance.

Run the following commands on the Tomcat server:

sudo find $CATALINA_BASE/temp -maxdepth 0 \\( ! -user tomcat \\) | sudo xargs chown tomcat

sudo find $CATALINA_BASE/temp -maxdepth 0 \\( ! -group tomcat \\) | sudo xargs chgrp tomcat'
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24661r426411_chk'
  tag severity: 'low'
  tag gid: 'V-222989'
  tag rid: 'SV-222989r615938_rule'
  tag stig_id: 'TCAT-AS-001260'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag fix_id: 'F-24650r426412_fix'
  tag 'documentable'
  tag legacy: ['SV-111501', 'V-102561']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
