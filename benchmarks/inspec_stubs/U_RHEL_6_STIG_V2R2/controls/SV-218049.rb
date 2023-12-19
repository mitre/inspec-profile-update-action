control 'SV-218049' do
  title 'The operating system must employ automated mechanisms, per organization defined frequency, to detect the addition of unauthorized components/devices into the operating system.'
  desc 'By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.'
  desc 'check', 'To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding.'
  desc 'fix', 'AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19530r377162_chk'
  tag severity: 'medium'
  tag gid: 'V-218049'
  tag rid: 'SV-218049r603264_rule'
  tag stig_id: 'RHEL-06-000303'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-19528r377163_fix'
  tag 'documentable'
  tag legacy: ['SV-50497', 'V-38696']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
