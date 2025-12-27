control 'SV-222944' do
  title 'Files in the $CATALINA_BASE/logs/ folder must have their permissions set to 640.'
  desc 'Tomcat file permissions must be restricted. The standard configuration is to have all Tomcat files owned by root with group Tomcat. While root has read/write privileges, group only has read permissions, and world has no permissions. The exceptions are the logs, temp, and work directories that are owned by the Tomcat user rather than root. This means that even if an attacker compromises the Tomcat process, they cannot change the Tomcat configuration, deploy new web applications, or modify existing web applications. The Tomcat process runs with a umask of 0027 to maintain these permissions.'
  desc 'check', 'Access the Tomcat server from the command line and execute the following OS command:

sudo find $CATALINA_BASE/logs/* -follow -maxdepth 0 -type f \\( \\! -perm 640 \\) -ls

If ISSM risk acceptance specifies deviation from requirement based on operational/application needs, this is not a finding if the permissions are set in accordance with the risk acceptance.

If no files are displayed, this is not a finding.

If results indicate any of the file permissions contained in the $CATALINA_BASE/logs folder are not set to 640, this is a finding.'
  desc 'fix', 'If operational/application requirements specify different file permissions, obtain ISSM risk acceptance and set permissions according to risk acceptance.

Run the following command on the Tomcat server:

sudo find $CATALINA_BASE/logs/* -follow -maxdepth 0 -type f -print0 | sudo xargs chmod 640 $CATALINA_BASE/logs/*'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24616r426276_chk'
  tag severity: 'medium'
  tag gid: 'V-222944'
  tag rid: 'SV-222944r615938_rule'
  tag stig_id: 'TCAT-AS-000361'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag fix_id: 'F-24605r426277_fix'
  tag 'documentable'
  tag legacy: ['SV-111417', 'V-102471']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
