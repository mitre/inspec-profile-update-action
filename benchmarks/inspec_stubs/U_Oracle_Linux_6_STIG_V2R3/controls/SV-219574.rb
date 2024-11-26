control 'SV-219574' do
  title 'The operating system must provide a near real-time alert when any of the organization defined list of compromise or potential compromise indicators occurs.'
  desc 'By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.'
  desc 'check', 'To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding.'
  desc 'fix', 'AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21299r358262_chk'
  tag severity: 'medium'
  tag gid: 'V-219574'
  tag rid: 'SV-219574r603263_rule'
  tag stig_id: 'OL6-00-000305'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-21298r358263_fix'
  tag 'documentable'
  tag legacy: ['V-51029', 'SV-65235']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
