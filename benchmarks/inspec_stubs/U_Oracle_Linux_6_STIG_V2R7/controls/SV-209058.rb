control 'SV-209058' do
  title 'The audit system must take appropriate action when the audit storage volume is full.'
  desc 'Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records.'
  desc 'check', 'Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to take appropriate action when the audit storage volume is full:

# grep disk_full_action /etc/audit/auditd.conf
disk_full_action = [ACTION]

If the system is configured to "suspend" when the volume is full or "ignore" that it is full, this is a finding.'
  desc 'fix', 'The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately: 

disk_full_action = [ACTION]

Possible values for [ACTION] are described in the "auditd.conf" man page. These include: 

"ignore"
"syslog"
"exec"
"suspend"
"single"
"halt"

Set this to "syslog", "exec", "single", or "halt".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9311r357959_chk'
  tag severity: 'medium'
  tag gid: 'V-209058'
  tag rid: 'SV-209058r793779_rule'
  tag stig_id: 'OL6-00-000510'
  tag gtitle: 'SRG-OS-000047'
  tag fix_id: 'F-9311r357960_fix'
  tag 'documentable'
  tag legacy: ['V-50601', 'SV-64807']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
