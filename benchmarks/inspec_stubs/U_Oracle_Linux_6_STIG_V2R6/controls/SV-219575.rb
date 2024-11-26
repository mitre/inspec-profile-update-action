control 'SV-219575' do
  title 'The operating system must detect unauthorized changes to software and information.'
  desc 'By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.'
  desc 'check', 'To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding.'
  desc 'fix', 'AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21300r358265_chk'
  tag severity: 'medium'
  tag gid: 'V-219575'
  tag rid: 'SV-219575r793832_rule'
  tag stig_id: 'OL6-00-000306'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-21299r358266_fix'
  tag 'documentable'
  tag legacy: ['SV-65241', 'V-51035']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
