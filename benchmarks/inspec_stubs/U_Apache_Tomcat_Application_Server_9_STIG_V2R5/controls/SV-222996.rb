control 'SV-222996' do
  title 'Tomcat server must be patched for security vulnerabilities.'
  desc 'Tomcat is constantly being updated to address newly discovered vulnerabilities, some of which include denial-of-service attacks. To address this risk, the Tomcat administrator must ensure the system remains up to date on patches.

'
  desc 'check', 'Refer to https://tomcat.apache.org/security-9.html and identify the latest secure version of Tomcat with no known vulnerabilities.

As a privileged user from the Tomcat server, run the following command:

sudo $CATALINA_HOME/bin/version.sh |grep -i server

Compare the version running on the system to the latest secure version of Tomcat.

Note: If TCAT-AS-000950 is compliant, users may need to leverage a different management interface. There is commonly a version.bat script in CATALINA_HOME/bin that will also output the current version of Tomcat.

If the latest secure version of Tomcat is not installed, this is a finding.'
  desc 'fix', 'Follow operational procedures for upgrading Tomcat. Download latest version of Tomcat and install in a test environment. Test applications that are running in production and follow all operations best practices when upgrading the production Tomcat application servers.

Update the Tomcat production instance accordingly and ensure corrected builds are installed once tested and verified.'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24668r850826_chk'
  tag severity: 'medium'
  tag gid: 'V-222996'
  tag rid: 'SV-222996r879806_rule'
  tag stig_id: 'TCAT-AS-001470'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-24657r426433_fix'
  tag satisfies: ['SRG-APP-000435-AS-000163', 'SRG-APP-000456-AS-000266']
  tag 'documentable'
  tag legacy: ['V-102575', 'SV-111515']
  tag cci: ['CCI-002385', 'CCI-002605']
  tag nist: ['SC-5 a', 'SI-2 c']
end
