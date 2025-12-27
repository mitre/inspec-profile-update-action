control 'SV-38856' do
  title 'The audit system must be configured to audit login, logout, and session initiation.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Check the system's audit configuration.
# more /etc/security/audit/events
Confirm the following events are configured:
USER_Login, USER_Logout, INIT_Start, INIT_End and USER_SU.
If any of these events are not present, this is a finding.

Check the USER_Login, USER_Logout, INIT_Start, INIT_End, and USER_SU audit events are defined in the audit classes' stanza 'classes:' of the /etc/security/audit/config file.
#more  /etc/security/audit/config
Make note of the audit class(es) the USER_Login, USER_Logout, INIT_Start, INIT_End, and USER_SU events are associated with.
If the USER_Login, USER_Logout, INIT_Start, INIT_End, and USER_SU events are not associated with any audit classes in the classes: stanza, this is a finding.

Verify the audit class is associated with the default user and all other user ids listed in the users: stanza of the /etc/security/audit/config file.
#more /etc/security/audit/config
If the class(es) the USER_Login, USER_Logout, INIT_Start, INIT_End, and USER_SU events are not associated with the default user and all the system users in the users: stanza,  this is a finding."
  desc 'fix', 'Edit /etc/security/audit/events and add the USER_Login, USER_Logout, INIT_Start, INIT_End, and USER_SU events to the list of audited events.  

Edit /etc/security/audit/config and add the USER_Login, USER_Logout, INIT_Start, INIT_End, and USER_SU audit events to an audit class in the classes: stanza.

Edit the /etc/security/audit/config and assign the audit classes with the USER_Login, USER_Logout, INIT_Start, INIT_End, and USER_SU events to the all users listed in the users: stanza.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37848r1_chk'
  tag severity: 'medium'
  tag gid: 'V-818'
  tag rid: 'SV-38856r1_rule'
  tag stig_id: 'GEN002800'
  tag gtitle: 'GEN002800'
  tag fix_id: 'F-33111r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
