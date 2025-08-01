control 'SV-208874' do
  title 'System logs must be rotated daily.'
  desc 'Log files that are not properly rotated run the risk of growing so large that they fill up the /var/log partition. Valuable logging information could be lost if the /var/log partition becomes full.'
  desc 'check', 'Run the following commands to determine the current status of the "logrotate" service: 

# grep logrotate /var/log/cron*

If the logrotate service is not run on a daily basis by cron, this is a finding.'
  desc 'fix', 'The "logrotate" service should be installed or reinstalled if it is not installed and operating properly, by running the following command:

# yum reinstall logrotate'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9127r357602_chk'
  tag severity: 'low'
  tag gid: 'V-208874'
  tag rid: 'SV-208874r793659_rule'
  tag stig_id: 'OL6-00-000138'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9127r357603_fix'
  tag 'documentable'
  tag legacy: ['SV-65227', 'V-51021']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
