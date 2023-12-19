control 'SV-27294' do
  title 'The audit system must be configured to audit file deletions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Check the system audit configuration to determine if failed attempts to access files and programs are audited.
# more /etc/security/audit/events
If auditing of the FILE_Unlink or FS_Rmdir events is not configured, this is a finding.
If no results are returned, this is a finding.

Check the FILE_Unlink and FS_Rmdir  audit event(s) are defined in the audit classes' stanza classes: of the /etc/security/audit/config file.

#more  /etc/security/audit/config
Make note of the audit class(es) that the File_Unlink and FS_Rmdir  events are associated with.
If the FILE_Unlink and FS_Rmdir  events are not associated with any audit classes in the classes: stanza this is a finding.

Verify the audit class is associated with the default user and all other user ids listed in the users: stanza of the /etc/security/audit/config file.
#more /etc/security/audit/config
If the class(es) that the FILE_Unlink and FS_Rmdir events are not associated with the default user and all the system users in the users: stanza,  this is a finding."
  desc 'fix', 'Edit /etc/security/audit/events and add the FILE_Unlink or FS_Rmdir events to the list of audited events.

Edit /etc/security/audit/config and add the FILE_Unlink and FS_Rmdir audit events to an audit class in the classes: stanza.

Edit the /etc/security/audit/config and assign the audit classes containing the FILE_Unlink and FS_Rmdir events to the all users listed in the users: stanza.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-815'
  tag rid: 'SV-27294r1_rule'
  tag stig_id: 'GEN002740'
  tag gtitle: 'GEN002740'
  tag fix_id: 'F-33106r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
