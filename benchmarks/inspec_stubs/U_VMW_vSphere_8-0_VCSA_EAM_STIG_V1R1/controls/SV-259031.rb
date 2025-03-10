control 'SV-259031' do
  title 'The vCenter ESX Agent Manager service default documentation must be removed.'
  desc 'Tomcat provides documentation and other directories in the default installation that do not serve a production use. These files must be deleted.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /var/opt/apache-tomcat/webapps/docs

If the "docs" folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /var/opt/apache-tomcat/webapps/docs'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA EAM'
  tag check_id: 'C-62771r934749_chk'
  tag severity: 'medium'
  tag gid: 'V-259031'
  tag rid: 'SV-259031r934751_rule'
  tag stig_id: 'VCEM-80-000143'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62680r934750_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
