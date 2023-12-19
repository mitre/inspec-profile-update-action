control 'SV-26519' do
  title 'The audit system must be configured to audit account creation.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises, and damages incurred during a system compromise.'
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
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-22376'
  tag rid: 'SV-26519r1_rule'
  tag stig_id: 'GEN002750'
  tag gtitle: 'GEN002750'
  tag fix_id: 'F-23761r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
