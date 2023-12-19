control 'SV-38850' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', %q(Check the system audit configuration to determine if failed attempts to access files and programs are audited.  
Check system activities (events) to audit are listed in the /etc/security/audit/events file.
Procedure:
# more /etc/security/audit/events
If the FILE_Open event is not configured, this is a finding.

Check the FILE_Open audit event is defined in the audit classes' stanza classes: of the /etc/security/audit/config file.
Procedure:
#more  /etc/security/audit/config
Make note of the audit class(es) that the FILE_Open  event is associated with.
If the FILE_Open event is not associated with any audit classes in the classes: stanza, this is a finding.

Verify the audit class is associated with the default user and all other user ids listed in the users: stanza of the /etc/security/audit/config file.
Procedure:
#more /etc/security/audit/config
If the class(es) the FILE_Open event is(/are) not associated with the default user and all the system users in the users: stanza,  this is a finding.

Supplementary Information:
Successful setup of AIX auditing requires several files and stanza's to be correctly configured.
1.	The /etc/security/audit/events must have the system call defined.
2.	The /etc/security/audit/config has 2 stanzas that need to be configured
a.	"classes:" stanza.   Each entry in this stanza defines two things.  The first is the name of a class to group the events to be audited on.  The class is linked to users of the system for auditing.  The second is the event(s) to be audited in this class: stanza.
Example:
classes:
DISA_CLASS = FILE_Open, File_Unlink, FS_Rmdir  

b.	"users:" stanza.   There are two options of specifying what users audit on.    The first is to explicitly spell out user names.
EXAMPLE:
users:
root = DISA_CLASS

The second is to specify a default catching all users not listed elsewhere in the users: stanza
EXAMPLE
users:
root =  DISA_CLASS
default = DISA_CLASS
3.	An approach to setup auditing to meet STIG requirements would be to create class stanza with all audit events that are required.   The users: stanza would then be populated with the root user,  any other user ids with special requirements and finally a default user.
4.	The /usr/lib/security/mkuser.default file can have under the users: stanza an entry 
auditclasses = class(es) of events to be audited for each new user added to the system.)
  desc 'fix', 'Edit /etc/security/audit/events and add the FILE_Open event to the list of audited events.

Edit /etc/security/audit/config and add the FILE_Open audit event to an audit class in the classes: stanza.

Edit the /etc/security/audit/config and assign the audit classes that have the FILE_Open event to the users listed in the users: stanza.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37842r1_chk'
  tag severity: 'medium'
  tag gid: 'V-814'
  tag rid: 'SV-38850r1_rule'
  tag stig_id: 'GEN002720'
  tag gtitle: 'GEN002720'
  tag fix_id: 'F-33105r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
