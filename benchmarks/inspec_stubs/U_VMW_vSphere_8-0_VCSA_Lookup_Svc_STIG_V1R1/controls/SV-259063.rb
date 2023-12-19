control 'SV-259063' do
  title 'The vCenter Lookup service example applications must be removed.'
  desc 'Tomcat provides example applications, documentation, and other directories in the default installation that do not serve a production use. These files must be deleted.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /var/opt/apache-tomcat/webapps/examples

If the examples folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /var/opt/apache-tomcat/webapps/examples'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Lookup Service'
  tag check_id: 'C-62803r934845_chk'
  tag severity: 'medium'
  tag gid: 'V-259063'
  tag rid: 'SV-259063r934847_rule'
  tag stig_id: 'VCLU-80-000141'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62712r934846_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
