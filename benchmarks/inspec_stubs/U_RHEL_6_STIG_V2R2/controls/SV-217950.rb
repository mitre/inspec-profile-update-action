control 'SV-217950' do
  title 'The audit system must switch the system to single-user mode when available audit storage volume becomes dangerously low.'
  desc 'Administrators should be made aware of an inability to record audit records. If a separate partition or logical volume of adequate size is used, running low on space for audit records should never occur.'
  desc 'check', 'Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to either suspend, switch to single-user mode, or halt when disk space has run low:

admin_space_left_action = single

If the system is not configured to switch to single-user mode, suspend, or halt for corrective action, this is a finding.'
  desc 'fix', 'The "auditd" service can be configured to take an action when disk space is running low but prior to running out of space completely. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting [ACTION] appropriately:

admin_space_left_action = [ACTION]

Set this value to "single" to cause the system to switch to single-user mode for corrective action. Acceptable values also include "suspend" and "halt". For certain systems, the need for availability outweighs the need to log all actions, and a different setting should be determined. Details regarding all possible values for [ACTION] are described in the "auditd.conf" man page.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19431r376865_chk'
  tag severity: 'medium'
  tag gid: 'V-217950'
  tag rid: 'SV-217950r603264_rule'
  tag stig_id: 'RHEL-06-000163'
  tag gtitle: 'SRG-OS-000343'
  tag fix_id: 'F-19429r376866_fix'
  tag 'documentable'
  tag legacy: ['V-54381', 'SV-68627']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
