control 'SV-222990' do
  title '$CATALINA_BASE/temp folder permissions must be set to 750.'
  desc "Tomcat's file permissions must be restricted. The standard configuration is to have all Tomcat files owned by root with the group Tomcat. While root has read/write privileges, tomcat group only has read and world has no permissions. The exceptions are the logs, temp and work directory that are owned by the Tomcat user rather than root. This means that even if an attacker compromises the Tomcat process, they cannot change the Tomcat configuration, deploy new web applications, or modify existing web applications. The Tomcat process runs with a umask of 007 to maintain these permissions.

If operational needs require application administrators to be able to change application configurations, the group permissions can be modified to allow specific application admins the access they require with an ISSM risk acceptance. Ownership may not change."
  desc 'check', 'Access the Tomcat server from the command line and execute the following OS command:

sudo find $CATALINA_BASE/temp -follow -maxdepth 0 -type d \\( \\! -perm 750 \\) -ls

If ISSM risk acceptance specifies deviation from requirement based on operational/application needs, this is not a finding if the permissions are set in accordance with the risk acceptance.

If no folders are displayed, this is not a finding.

If results indicate the $CATALINA_BASE/temp folder permissions are not set to 750, this is a finding.'
  desc 'fix', 'If operational/application requirements specify different file permissions, obtain ISSM risk acceptance and set permissions according to risk acceptance.

Run the following commands on the Tomcat server:

sudo find  $CATALINA_BASE/temp -follow -maxdepth 0 -type d -print0 | sudo xargs chmod 750 $CATALINA_BASE/temp'
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24662r426414_chk'
  tag severity: 'low'
  tag gid: 'V-222990'
  tag rid: 'SV-222990r615938_rule'
  tag stig_id: 'TCAT-AS-001270'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag fix_id: 'F-24651r426415_fix'
  tag 'documentable'
  tag legacy: ['SV-111503', 'V-102563']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
