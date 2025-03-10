control 'SV-218397' do
  title 'The audit system must be configured to audit account termination.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Determine if execution of the userdel and groupdel executable are audited.
# auditctl -l | egrep '(userdel|groupdel)'
If either userdel or groupdel are not listed with a permissions filter of at least 'x', this is a finding."
  desc 'fix', 'Configure execute auditing of the userdel and groupdel executables. Add the following to the audit.rules file:
-w /usr/sbin/userdel -p x 
-w /usr/sbin/groupdel -p x

Restart the auditd service.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19872r554528_chk'
  tag severity: 'low'
  tag gid: 'V-218397'
  tag rid: 'SV-218397r603259_rule'
  tag stig_id: 'GEN002753'
  tag gtitle: 'SRG-OS-000241-GPOS-00091'
  tag fix_id: 'F-19870r554529_fix'
  tag 'documentable'
  tag legacy: ['V-22382', 'SV-64273']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
