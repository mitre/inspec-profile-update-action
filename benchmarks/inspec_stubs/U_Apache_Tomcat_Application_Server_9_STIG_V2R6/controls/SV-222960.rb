control 'SV-222960' do
  title 'Documentation must be removed.'
  desc 'Tomcat provides documentation and other directories in the default installation which do not serve a production use. These files must be deleted.'
  desc 'check', 'From the Tomcat server OS type the following command:

sudo ls -l $CATALINA_BASE/webapps/docs.

If the docs folder exists or contains any content, this is a finding.'
  desc 'fix', 'From the Tomcat server OS type the following command:

sudo rm -rf $CATALINA_BASE/webapps/docs'
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24632r426324_chk'
  tag severity: 'low'
  tag gid: 'V-222960'
  tag rid: 'SV-222960r879587_rule'
  tag stig_id: 'TCAT-AS-000580'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-24621r426325_fix'
  tag 'documentable'
  tag legacy: ['SV-111445', 'V-102503']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
