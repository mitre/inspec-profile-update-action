control 'SV-218094' do
  title 'The audit system must take appropriate action when there are disk errors on the audit storage volume.'
  desc 'Taking appropriate action in case of disk errors will minimize the possibility of losing audit records.'
  desc 'check', 'Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to take appropriate action when disk errors occur:

# grep disk_error_action /etc/audit/auditd.conf
disk_error_action = [ACTION]


If the system is configured to "suspend" when disk errors occur or "ignore" them, this is a finding.'
  desc 'fix', 'Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately: 

disk_error_action = [ACTION]

Possible values for [ACTION] are described in the "auditd.conf" man page. These include: 

"ignore"
"syslog"
"exec"
"suspend"
"single"
"halt"


Set this to "syslog", "exec", "single", or "halt".'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19575r377297_chk'
  tag severity: 'medium'
  tag gid: 'V-218094'
  tag rid: 'SV-218094r603264_rule'
  tag stig_id: 'RHEL-06-000511'
  tag gtitle: 'SRG-OS-000047'
  tag fix_id: 'F-19573r377298_fix'
  tag 'documentable'
  tag legacy: ['SV-50264', 'V-38464']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
