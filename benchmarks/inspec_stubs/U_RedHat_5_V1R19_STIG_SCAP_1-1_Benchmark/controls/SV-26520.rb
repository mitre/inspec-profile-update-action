control 'SV-26520' do
  title 'The audit system must be configured to audit account modification.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
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
