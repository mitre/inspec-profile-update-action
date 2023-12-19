control 'SV-219571' do
  title 'A file integrity tool must be used at least weekly to check for unauthorized file changes, particularly the addition of unauthorized system libraries or binaries, or for unauthorized modification to authorized system libraries or binaries.'
  desc 'By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.'
  desc 'check', 'To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, or if aide is not run at least weekly, this is a finding.'
  desc 'fix', 'AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21296r358253_chk'
  tag severity: 'medium'
  tag gid: 'V-219571'
  tag rid: 'SV-219571r793828_rule'
  tag stig_id: 'OL6-00-000302'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-21295r358254_fix'
  tag 'documentable'
  tag legacy: ['SV-65217', 'V-51011']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
