control 'SV-227730' do
  title 'The audit system must be configured to audit account disabling.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Check the system's audit configuration.

# grep ua /etc/security/audit_control

If the ua flag is not set, and both the +ua and -ua flags are not set, this is a finding.
If the ua naflag is not set, and both the +ua and -ua naflags are not set, this is a finding."
  desc 'fix', 'Edit /etc/security/audit_control and add ua to the flags list and naflags list.
Refresh auditd.
# svcadm refresh auditd'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29892r488774_chk'
  tag severity: 'low'
  tag gid: 'V-227730'
  tag rid: 'SV-227730r603266_rule'
  tag stig_id: 'GEN002752'
  tag gtitle: 'SRG-OS-000240'
  tag fix_id: 'F-29880r488775_fix'
  tag 'documentable'
  tag legacy: ['V-22378', 'SV-40610']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
