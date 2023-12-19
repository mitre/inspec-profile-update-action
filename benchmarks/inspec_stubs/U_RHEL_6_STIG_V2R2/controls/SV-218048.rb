control 'SV-218048' do
  title 'A file integrity tool must be used at least weekly to check for unauthorized file changes, particularly the addition of unauthorized system libraries or binaries, or for unauthorized modification to authorized system libraries or binaries.'
  desc 'By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.'
  desc 'check', 'To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output or if aide is not run at least weekly, this is a finding.'
  desc 'fix', 'AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19529r377159_chk'
  tag severity: 'medium'
  tag gid: 'V-218048'
  tag rid: 'SV-218048r603264_rule'
  tag stig_id: 'RHEL-06-000302'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-19527r377160_fix'
  tag 'documentable'
  tag legacy: ['V-38695', 'SV-50496']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
