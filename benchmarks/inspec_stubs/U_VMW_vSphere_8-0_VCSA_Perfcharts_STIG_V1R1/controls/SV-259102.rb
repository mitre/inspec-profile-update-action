control 'SV-259102' do
  title 'The vCenter Perfcharts service manager webapp must be removed.'
  desc 'Tomcat provides management functionality through either a default manager webapp or through local editing of the configuration files. The manager webapp files must be deleted, and administration must be performed through the local editing of the configuration files.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /usr/lib/vmware-perfcharts/tc-instance/webapps/manager

If the manager folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /usr/lib/vmware-perfcharts/tc-instance/webapps/manager'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Perfcharts'
  tag check_id: 'C-62842r934962_chk'
  tag severity: 'medium'
  tag gid: 'V-259102'
  tag rid: 'SV-259102r934964_rule'
  tag stig_id: 'VCPF-80-000154'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62751r934963_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
