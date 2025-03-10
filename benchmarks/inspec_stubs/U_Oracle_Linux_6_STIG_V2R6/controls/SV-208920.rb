control 'SV-208920' do
  title 'The cron service must be running.'
  desc 'Due to its usage for maintenance and security-supporting tasks, enabling the cron daemon is essential.'
  desc 'check', 'Run the following command to determine the current status of the "crond" service: 

# service crond status

If the service is enabled, it should return the following: 

crond is running...

If the service is not running, this is a finding.'
  desc 'fix', 'The "crond" service is used to execute commands at preconfigured times. It is required by almost all systems to perform necessary maintenance tasks, such as notifying root of system activity. The "crond" service can be enabled with the following commands: 

# chkconfig crond on
# service crond start'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9173r357740_chk'
  tag severity: 'medium'
  tag gid: 'V-208920'
  tag rid: 'SV-208920r793706_rule'
  tag stig_id: 'OL6-00-000224'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9173r357741_fix'
  tag 'documentable'
  tag legacy: ['V-50571', 'SV-64777']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
