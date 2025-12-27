control 'SV-38853' do
  title 'The audit system must be configured to audit account disabling.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Determine if the system is configured to audit account disabling. 
Procedure:
# more /etc/security/audit/events
If auditing of the USER_Change and USER_Locked events are not configured, this is a finding.

Check the USER_Change and USER_Locked audit event(s) are defined in the audit classes' stanza classes: of the /etc/security/audit/config file.
Procedure:
#more  /etc/security/audit/config
Make note of the audit class(es) the USER_Change and USER_Locked events are associated with.
If the USER_Change and USER_Locked events are not associated with any audit classes in the classes: stanza, this is a finding.

Verify the audit class is associated with the default user and all other user ids listed in the users: stanza of the /etc/security/audit/config file.

Procedure:
#more /etc/security/audit/config
If the class(es) the USER_Change and USER_Locked events are not associated with the default user and all the system users in the users: stanza,  this is a finding."
  desc 'fix', 'Configure the system to audit account disabling. 

Edit /etc/security/audit/events and add the USER_Change and USER_Locked events to the list of audited events.

Edit /etc/security/audit/config and add the USER_Change and USER_Locked audits event to an audit class in the classes: stanza.

Edit the /etc/security/audit/config and assign the audit classes with the USER_Change and USER_Locked events to the all users listed in the users: stanza.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37846r1_chk'
  tag severity: 'low'
  tag gid: 'V-22378'
  tag rid: 'SV-38853r1_rule'
  tag stig_id: 'GEN002752'
  tag gtitle: 'GEN002752'
  tag fix_id: 'F-33109r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
