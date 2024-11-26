control 'SV-222948' do
  title '$CATALINA_HOME/bin folder permissions must be set to 750.'
  desc 'Tomcat file permissions must be restricted. The standard configuration is to have all Tomcat files owned by root with group Tomcat. While root has read/write privileges, group only has read permissions, and world has no permissions. The exceptions are the logs, temp, and work directories that are owned by the Tomcat user rather than root. This means that even if an attacker compromises the Tomcat process, they cannot change the Tomcat configuration, deploy new web applications, or modify existing web applications. The Tomcat process runs with a umask of 0027 to maintain these permissions. Note that running Tomcat in a Docker environment can impact how file permissions and user ownership settings are applied. Due to associated Docker configuration complexities, the STIG is scoped for standalone rather than virtual Docker deployments.

'
  desc 'check', 'Access the Tomcat server from the command line and execute the following OS command:

sudo find $CATALINA_HOME/bin -follow -maxdepth 0 -type d \\( \\! -perm 750 \\) -ls

If no folders are displayed, this is not a finding.

If results indicate the $CATALINA_HOME/bin folder permissions are not set to 750, this is a finding.'
  desc 'fix', 'Run the following command on the Tomcat server:

sudo find $CATALINA_HOME/bin -follow -maxdepth 0 -type d -print0 | sudo xargs chmod 750 $CATALINA_HOME/bin'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24620r426288_chk'
  tag severity: 'medium'
  tag gid: 'V-222948'
  tag rid: 'SV-222948r754841_rule'
  tag stig_id: 'TCAT-AS-000390'
  tag gtitle: 'SRG-APP-000121-AS-000081'
  tag fix_id: 'F-24609r426289_fix'
  tag satisfies: ['SRG-APP-000121-AS-000081', 'SRG-APP-000122-AS-000082', 'SRG-APP-000123-AS-000083', 'SRG-APP-000340-AS-000185']
  tag 'documentable'
  tag legacy: ['SV-111553', 'V-102607']
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-002235']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9', 'AC-6 (10)']
end
