control 'SV-26520' do
  title 'The audit system must be configured to audit account modification.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Determine if execution of the usermod and groupmod executable are audited.
# auditctl -l | egrep '(usermod|groupmod)'
If either useradd or groupadd are not listed with a permissions filter of at least 'w', this is a finding.
Determine if /etc/passwd, /etc/shadow, /etc/group, and /etc/gshadow are audited for writing.
# auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)'
If any of these are not listed with a permissions filter of at least 'w', this is a finding."
  desc 'fix', 'Configure execute auditing of the usermod and groupmod executables.  Add the following to the audit.rules file:
-w /usr/sbin/usermod -p x -k usermod
-w /usr/sbin/groupmod -p x -k groupmod
Configure append auditing of the passwd, shadow, group, and gshadow files.  Add the following to the audit.rules file:
-w /etc/passwd -p w -k passwd
-w /etc/shadow -p w -k shadow
-w /etc/group -p w -k group
-w /etc/gshadow -p w -k gshadow
Restart the auditd service.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-27573r1_chk'
  tag severity: 'low'
  tag gid: 'V-22377'
  tag rid: 'SV-26520r1_rule'
  tag stig_id: 'GEN002751'
  tag gtitle: 'GEN002751'
  tag fix_id: 'F-23762r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
