control 'SV-227728' do
  title 'The audit system must be configured to audit account creation.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises, and damages incurred during a system compromise.'
  desc 'check', "Check the system's audit configuration.

# grep ua /etc/security/audit_control

If the ua flag is not set, and both the +ua and -ua flags are not set, this is a finding.
If the ua naflag is not set, and both the +ua and -ua naflags are not set, this is a finding."
  desc 'fix', 'Edit /etc/security/audit_control and add ua to the flags list and naflags list.
Refresh auditd.
# svcadm refresh auditd'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29890r488768_chk'
  tag severity: 'low'
  tag gid: 'V-227728'
  tag rid: 'SV-227728r603266_rule'
  tag stig_id: 'GEN002750'
  tag gtitle: 'SRG-OS-000004'
  tag fix_id: 'F-29878r488769_fix'
  tag 'documentable'
  tag legacy: ['V-22376', 'SV-40605']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
