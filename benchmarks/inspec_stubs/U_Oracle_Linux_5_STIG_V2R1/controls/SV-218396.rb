control 'SV-218396' do
  title 'The audit system must be configured to audit account disabling.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Determine if execution of the passwd executable is audited.
# auditctl -l | grep /usr/bin/passwd
If passwd is not listed with a permissions filter of at least 'x', this is a finding."
  desc 'fix', 'Configure execute auditing of the passwd executable.  Add the following to the audit.rules file:
-w /usr/bin/passwd -p x -k passwd

Restart the auditd service.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19871r554525_chk'
  tag severity: 'low'
  tag gid: 'V-218396'
  tag rid: 'SV-218396r603259_rule'
  tag stig_id: 'GEN002752'
  tag gtitle: 'SRG-OS-000240-GPOS-00090'
  tag fix_id: 'F-19869r554526_fix'
  tag 'documentable'
  tag legacy: ['V-22378', 'SV-64271']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
