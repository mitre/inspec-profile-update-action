control 'SV-208878' do
  title 'The system must retain enough rotated audit logs to cover the required log retention period.'
  desc 'The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained.'
  desc 'check', %q(Inspect "/etc/audit/auditd.conf" and locate the following line to determine how many logs the system is configured to retain after rotation: "# grep num_logs /etc/audit/auditd.conf" 

num_logs = 5

If the overall system log file(s) retention hasn't been properly set up, this is a finding.)
  desc 'fix', 'Determine how many log files "auditd" should retain when it rotates logs. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting [NUMLOGS] with the correct value: 

num_logs = [NUMLOGS]

Set the value to 5 for general-purpose systems. Note that values less than 2 result in no log rotation.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9131r357614_chk'
  tag severity: 'medium'
  tag gid: 'V-208878'
  tag rid: 'SV-208878r793663_rule'
  tag stig_id: 'OL6-00-000159'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9131r357615_fix'
  tag 'documentable'
  tag legacy: ['SV-65249', 'V-51043']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
