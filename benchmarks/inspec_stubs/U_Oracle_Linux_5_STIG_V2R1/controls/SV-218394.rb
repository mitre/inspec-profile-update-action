control 'SV-218394' do
  title 'The audit system must be configured to audit account creation.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises, and damages incurred during a system compromise.'
  desc 'check', "Determine if execution of the useradd and groupadd executable are audited.
# auditctl -l | egrep '(useradd|groupadd)'
If either useradd or groupadd are not listed with a permissions filter of at least 'x', this is a finding.
Determine if /etc/passwd, /etc/shadow, /etc/group, and /etc/gshadow are audited for appending.
# auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)'
If any of these are not listed with a permissions filter of at least 'a', this is a finding."
  desc 'fix', 'Configure execute auditing of the useradd and groupadd executables.
Add the following to audit.rules:
-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd
Configure append auditing of the passwd, shadow, group, and gshadow files.  Add the following to audit.rules:
-w /etc/passwd -p a -k passwd
-w /etc/shadow -p a -k shadow
-w /etc/group -p a -k group
-w /etc/gshadow -p a -k gshadow
Restart the auditd service.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19869r554519_chk'
  tag severity: 'low'
  tag gid: 'V-218394'
  tag rid: 'SV-218394r603259_rule'
  tag stig_id: 'GEN002750'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-19867r554520_fix'
  tag 'documentable'
  tag legacy: ['V-22376', 'SV-64267']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
