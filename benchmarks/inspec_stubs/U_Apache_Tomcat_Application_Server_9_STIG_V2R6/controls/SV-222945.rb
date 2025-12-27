control 'SV-222945' do
  title 'Files in the $CATALINA_BASE/conf/ folder must have their permissions set to 640.'
  desc 'Tomcat file permissions must be restricted. The standard configuration is to have all Tomcat files owned by root with group Tomcat. While root has read/write privileges, group only has read permissions, and world has no permissions. The exceptions are the logs, temp, and work directories that are owned by the Tomcat user group tomcat rather than root user group tomcat. This means that even if an attacker compromises the Tomcat process, they cannot change the Tomcat configuration, deploy new web applications, or modify existing web applications. The Tomcat process runs with a umask of 0027 to maintain these permissions.

If the ISSM determines the operational need to allow application admins access to change the Tomcat configuration outweighs the risk of limiting that access, then they can change the group membership to accommodate. Ownership must not be changed. The ISSM should take the exposure of the system to high risk networks into account.

'
  desc 'check', 'Access the Tomcat server from the command line and execute the following OS command:

sudo find $CATALINA_BASE/conf/* -follow -maxdepth 0 -type f \\( \\! -perm 640 \\) -ls

If ISSM risk acceptance specifies deviation from requirement based on operational/application needs, this is not a finding if the permissions are set in accordance with the risk acceptance.

If no files are displayed, this is not a finding.

If results indicate any of the file permissions contained in the $CATALINA_BASE/conf folder are not set to 640, this is a finding.'
  desc 'fix', 'If operational/application requirements specify different file permissions, obtain ISSM risk acceptance and set permissions according to risk acceptance.

Run the following command on the Tomcat server:

sudo find $CATALINA_BASE/conf/* -follow -maxdepth 0 -type f -print0 | sudo xargs chmod 640 $CATALINA_BASE/conf/*'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24617r426279_chk'
  tag severity: 'medium'
  tag gid: 'V-222945'
  tag rid: 'SV-222945r879577_rule'
  tag stig_id: 'TCAT-AS-000370'
  tag gtitle: 'SRG-APP-000119-AS-000079'
  tag fix_id: 'F-24606r426280_fix'
  tag satisfies: ['SRG-APP-000119-AS-000079', 'SRG-APP-000380-AS-000088']
  tag 'documentable'
  tag legacy: ['SV-111419', 'V-102473']
  tag cci: ['CCI-000163', 'CCI-001813']
  tag nist: ['AU-9 a', 'CM-5 (1) (a)']
end
