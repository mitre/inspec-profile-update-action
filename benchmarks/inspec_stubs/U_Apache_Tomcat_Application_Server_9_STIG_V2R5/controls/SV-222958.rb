control 'SV-222958' do
  title 'Example applications must be removed.'
  desc 'Tomcat provides example applications, documentation, and other directories in the default installation which do not serve a production use. These files must be deleted.'
  desc 'check', 'From the Tomcat server OS type the following command:

sudo ls -l $CATALINA_BASE/webapps/examples. 

If the examples folder exists or contains any content, this is a finding.'
  desc 'fix', 'From the Tomcat server OS type the following command:

 sudo rm -rf $CATALINA_BASE/webapps/examples'
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24630r426318_chk'
  tag severity: 'low'
  tag gid: 'V-222958'
  tag rid: 'SV-222958r879587_rule'
  tag stig_id: 'TCAT-AS-000560'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-24619r426319_fix'
  tag 'documentable'
  tag legacy: ['SV-111441', 'V-102499']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
