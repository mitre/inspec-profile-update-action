control 'SV-219576' do
  title 'The operating system must ensure unauthorized, security-relevant configuration changes detected are tracked.'
  desc 'By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.'
  desc 'check', 'To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding.'
  desc 'fix', 'AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21301r358268_chk'
  tag severity: 'medium'
  tag gid: 'V-219576'
  tag rid: 'SV-219576r603263_rule'
  tag stig_id: 'OL6-00-000307'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-21300r358269_fix'
  tag 'documentable'
  tag legacy: ['V-51037', 'SV-65243']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
