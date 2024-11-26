control 'SV-38857' do
  title 'The audit system must be configured to audit all discretionary access control permission modifications.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Check the system's audit configuration.
# more /etc/security/audit/events
Confirm the following events are configured:
FILE_Acl, FILE_Fchmod, FILE_Fchown, FILE_Mode, and 
FILE_Owner.
If any of these events are not configured, this is a finding.

Check the FILE_Acl, FILE_Fchmod, FILE_Fchown, FILE_Mode, and FILE_Owner audit events are defined in the audit classes' stanza classes: of the /etc/security/audit/config file.
#more  /etc/security/audit/config
Make note of the audit class(es) the FILE_Acl, FILE_Fchmod, FILE_Fchown, FILE_Mode, and 
FILE_Owner events are associated with.

If the FILE_Acl, FILE_Fchmod, FILE_Fchown, FILE_Mode, and 
FILE_Owner events are not associated with any audit classes in the classes: stanza, this is a finding.

Verify the audit class is associated with the default user and all other user ids listed in the users: stanza of the /etc/security/audit/config file.

If the class(es) the FILE_Acl, FILE_Fchmod, FILE_Fchown, FILE_Mode, and FILE_Owner events are not associated with the default user and all the system users in the users: stanza, this is a finding."
  desc 'fix', 'Edit /etc/security/audit/events and add the FILE_Acl, FILE_Fchmod, FILE_Fchown, FILE_Mode, and FILE_Owner events to the list of audited events.  

Edit /etc/security/audit/config and add the FILE_Acl, FILE_Fchmod, FILE_Fchown, FILE_Mode, and FILE_Owner audit events to an audit class in the classes: stanza.

Edit the /etc/security/audit/config and assign the audit classes with the FILE_Acl, FILE_Fchmod, FILE_Fchown, FILE_Mode, and FILE_Owner events to the all users listed in the users: stanza.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37849r1_chk'
  tag severity: 'medium'
  tag gid: 'V-819'
  tag rid: 'SV-38857r1_rule'
  tag stig_id: 'GEN002820'
  tag gtitle: 'GEN002820'
  tag fix_id: 'F-33112r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
