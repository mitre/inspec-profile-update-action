control 'SV-259103' do
  title 'The vCenter Perfcharts service host-manager webapp must be removed.'
  desc 'Tomcat provides host management functionality through either a default host-manager webapp or through local editing of the configuration files. The host-manager webapp files must be deleted, and administration must be performed through the local editing of the configuration files.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /usr/lib/vmware-perfcharts/tc-instance/webapps/host-manager

If the manager folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /usr/lib/vmware-perfcharts/tc-instance/webapps/host-manager'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Perfcharts'
  tag check_id: 'C-62843r934965_chk'
  tag severity: 'medium'
  tag gid: 'V-259103'
  tag rid: 'SV-259103r934967_rule'
  tag stig_id: 'VCPF-80-000155'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62752r934966_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
