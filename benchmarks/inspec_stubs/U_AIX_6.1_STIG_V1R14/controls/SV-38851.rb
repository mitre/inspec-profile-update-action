control 'SV-38851' do
  title 'The audit system must be configured to audit account creation.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises, and damages incurred during a system compromise.'
  desc 'check', "Determine if the audit system is configured to audit account creation. 

Procedure:
# more /etc/security/audit/events
If auditing of the USER_Create event is not configured, check the USER_Create  audit event is defined in the audit classes' stanza of the /etc/security/audit/config file.

Procedure:
#more  /etc/security/audit/config
Make note of the audit class the USER_Create  event is associated with.
If the USER_Create  event is not associated with any audit classes in the classes: stanza, this is a finding.

Verify the audit class is associated with the default user and all other user ids listed in the users: stanza of  the /etc/security/audit/config file.
Procedure:
#more /etc/security/audit/config
If the class(es) the USER_Create event is not associated with the default user and all the system users in the 'users:' stanza,  this is a finding."
  desc 'fix', 'Configure the audit system to audit account creation.  

Edit /etc/security/audit/events and add the User_Create event to the list of audited events.

Edit /etc/security/audit/config and add the USER_Create audit event to an audit class in the classes: stanza.

Edit the /etc/security/audit/config and assign the audit classes with the USER_Create event to the all users listed in the users: stanza.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37844r1_chk'
  tag severity: 'low'
  tag gid: 'V-22376'
  tag rid: 'SV-38851r1_rule'
  tag stig_id: 'GEN002750'
  tag gtitle: 'GEN002750'
  tag fix_id: 'F-33107r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
