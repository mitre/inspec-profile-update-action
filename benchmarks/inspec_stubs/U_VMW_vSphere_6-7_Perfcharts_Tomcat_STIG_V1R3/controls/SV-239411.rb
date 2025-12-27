control 'SV-239411' do
  title 'Performance Charts must not be configured with unsupported realms.'
  desc 'Performance Charts performs user authentication at the application level and not through Tomcat. Depending on the VCSA version, Performance Charts may come configured with a "UserDatabaseRealm". This should be removed as part of eliminating unnecessary features.'
  desc 'check', 'At the command prompt, execute the following command:

# grep UserDatabaseRealm /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

If the command produces any output, this is a finding.'
  desc 'fix', 'Navigate to and open /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml.

Remove the <Realm> node returned in the check.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Perfcharts Tomcat'
  tag check_id: 'C-42644r674954_chk'
  tag severity: 'medium'
  tag gid: 'V-239411'
  tag rid: 'SV-239411r879587_rule'
  tag stig_id: 'VCPF-67-000010'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-42603r674955_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
