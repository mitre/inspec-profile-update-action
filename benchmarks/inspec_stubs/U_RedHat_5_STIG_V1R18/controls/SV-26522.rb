control 'SV-26522' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37216r1_chk'
  tag severity: 'low'
  tag gid: 'V-22382'
  tag rid: 'SV-26522r1_rule'
  tag stig_id: 'GEN002753'
  tag gtitle: 'GEN002753'
  tag fix_id: 'F-32432r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
