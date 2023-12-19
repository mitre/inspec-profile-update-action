control 'SV-259130' do
  title 'The vCenter UI service example applications must be removed.'
  desc 'Tomcat provides example applications, documentation, and other directories in the default installation that do not serve a production use. These files must be deleted.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /usr/lib/vmware-vsphere-ui/server/webapps/examples

If the examples folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /usr/lib/vmware-vsphere-ui/server/webapps/examples'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA User Interface (UI)'
  tag check_id: 'C-62870r935292_chk'
  tag severity: 'medium'
  tag gid: 'V-259130'
  tag rid: 'SV-259130r935294_rule'
  tag stig_id: 'VCUI-80-000141'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62779r935293_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
