control 'SV-218053' do
  title 'The operating system must ensure unauthorized, security-relevant configuration changes detected are tracked.'
  desc 'By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.'
  desc 'check', 'To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding.'
  desc 'fix', 'AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19534r377174_chk'
  tag severity: 'medium'
  tag gid: 'V-218053'
  tag rid: 'SV-218053r603264_rule'
  tag stig_id: 'RHEL-06-000307'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-19532r377175_fix'
  tag 'documentable'
  tag legacy: ['SV-50474', 'V-38673']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
