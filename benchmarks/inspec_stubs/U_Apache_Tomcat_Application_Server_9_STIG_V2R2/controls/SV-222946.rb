control 'SV-222946' do
  title '$CATALINA_BASE/conf folder permissions must be set to 750.'
  desc 'Tomcat file permissions must be restricted. The standard configuration is to have all Tomcat files owned by root with group Tomcat. While root has read/write privileges, group only has read permissions, and world has no permissions. The exceptions are the logs, temp, and work directories that are owned by the Tomcat user rather than root. This means that even if an attacker compromises the Tomcat process, they cannot change the Tomcat configuration, deploy new web applications, or modify existing web applications. The Tomcat process runs with a umask of 007 to maintain these permissions.

If the ISSM determines the operational need to allow application admins access to change the Tomcat configuration outweighs the risk of limiting that access, then they can change the group membership to accommodate. Ownership must not be changed. The ISSM should take the exposure of the system to high risk networks into account.

'
  desc 'check', 'Access the Tomcat server from the command line and execute the following OS command:

sudo find $CATALINA_BASE/conf -follow -maxdepth 0 -type d \\( \\! -perm 750 \\) -ls

If ISSM risk acceptance specifies deviation from requirement based on operational/application needs, this is not a finding if the permissions are set in accordance with the risk acceptance.

If no folders are displayed, this is not a finding.

If results indicate the $CATALINA_BASE/conf folder permissions are not set to 750, this is a finding.'
  desc 'fix', 'If operational/application requirements specify different file permissions, obtain ISSM risk acceptance and set permissions according to risk acceptance.

Run the following command on the Tomcat server:

sudo find $CATALINA_BASE/conf -follow -maxdepth 0 -type d -print0 | sudo xargs chmod 750 $CATALINA_BASE/conf'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24618r426282_chk'
  tag severity: 'medium'
  tag gid: 'V-222946'
  tag rid: 'SV-222946r615938_rule'
  tag stig_id: 'TCAT-AS-000371'
  tag gtitle: 'SRG-APP-000119-AS-000079'
  tag fix_id: 'F-24607r426283_fix'
  tag satisfies: ['SRG-APP-000119-AS-000079', 'SRG-APP-000380-AS-000088']
  tag 'documentable'
  tag legacy: ['SV-111551', 'V-102605']
  tag cci: ['CCI-000163', 'CCI-001813']
  tag nist: ['AU-9 a', 'CM-5 (1) (a)']
end
