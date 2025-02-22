control 'SV-208879' do
  title 'The system must set a maximum audit log file size.'
  desc 'The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained.'
  desc 'check', %q(Inspect "/etc/audit/auditd.conf" and locate the following line to determine how much data the system will retain in each audit log file: "# grep max_log_file /etc/audit/auditd.conf" 

max_log_file = 6

If the system audit data threshold hasn't been properly set up, this is a finding.)
  desc 'fix', 'Determine the amount of audit data (in megabytes) which should be retained in each log file. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting the correct value for [STOREMB]: 

max_log_file = [STOREMB]

Set the value to "6" (MB) or higher for general-purpose systems. Larger values, of course, support retention of even more audit data.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9132r357617_chk'
  tag severity: 'medium'
  tag gid: 'V-208879'
  tag rid: 'SV-208879r603263_rule'
  tag stig_id: 'OL6-00-000160'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9132r357618_fix'
  tag 'documentable'
  tag legacy: ['SV-65255', 'V-51049']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
