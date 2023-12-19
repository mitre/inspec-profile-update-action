control 'SV-45319' do
  title 'The audit system must be configured to audit account disabling.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Determine if execution of the passwd executable is audited.
# auditctl -l | grep /usr/bin/passwd
If passwd is not listed with a permissions filter of at least 'x', this is a finding."
  desc 'fix', 'Configure execute auditing of the passwd executable. Add the following to the audit.rules file:
-w /usr/sbin/passwd -p x -k passwd

Restart the auditd service.   
# rcauditd restart
          OR
# service auditd restart'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42666r1_chk'
  tag severity: 'low'
  tag gid: 'V-22378'
  tag rid: 'SV-45319r1_rule'
  tag stig_id: 'GEN002752'
  tag gtitle: 'GEN002752'
  tag fix_id: 'F-38715r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
