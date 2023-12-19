control 'SV-259029' do
  title 'The vCenter ESX Agent Manager service example applications must be removed.'
  desc 'Tomcat provides example applications, documentation, and other directories in the default installation that do not serve a production use. These files must be deleted.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /var/opt/apache-tomcat/webapps/examples

If the examples folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /var/opt/apache-tomcat/webapps/examples'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA EAM'
  tag check_id: 'C-62769r934743_chk'
  tag severity: 'medium'
  tag gid: 'V-259029'
  tag rid: 'SV-259029r934745_rule'
  tag stig_id: 'VCEM-80-000141'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62678r934744_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
