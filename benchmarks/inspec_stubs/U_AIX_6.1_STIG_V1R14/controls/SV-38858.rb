control 'SV-38858' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'Actions concerning dynamic kernel modules must be recorded as they are substantial events.  Dynamic kernel modules can increase the attack surface of a system.  A malicious kernel module can be used to substantially alter the functioning of a system, often with the purpose of hiding a compromise from the SA.'
  desc 'check', "Determine if the system is configured to audit the loading and unloading of dynamic kernel modules. 

Check the system's audit configuration.
# more /etc/security/audit/events
Confirm the following events are configured:
DEV_Create, FILE_Mknod, DEV_Configure, DEV_Stop, DEV_Unconfigure, and DEV_Remove.
If any of these events are not configured, this is a finding.

Check the File DEV_Create, FILE_Mknod, DEV_Configure, DEV_Stop, DEV_Unconfigure, and DEV_Remove.  Audit events are defined in the audit classes stanza classes: of the /etc/security/audit/config file.
#more  /etc/security/audit/config
Make note of the audit class(es) the DEV_Create, FILE_Mknod, DEV_Configure, DEV_Stop, DEV_Unconfigure, and DEV_Remove  events are associated with.

If the DEV_Create, FILE_Mknod, DEV_Configure, DEV_Stop, DEV_Unconfigure, and DEV_Remove  events are not associated with any audit classes in the classes: stanza, this is a finding.

Verify the audit class is associated with the default user and all other user ids listed in the users: stanza of the /etc/security/audit/config file.

#more /etc/security/audit/config
If the class(es) that the DEV_Create, FILE_Mknod, DEV_Configure, DEV_Stop, DEV_Unconfigure, and DEV_Remove events are not associated with the default user and all the system users in the users: stanza,  this is a finding."
  desc 'fix', "Configure the system to audit the loading and unloading of dynamic kernel modules.

Edit /etc/security/audit/events and add the DEV_Create, FILE_Mknod, DEV_Configure, DEV_Stop, DEV_Unconfigure, and DEV_Remove events to the list of audited events.

Edit /etc/security/audit/config and add the DEV_Create, FILE_Mknod, DEV_Configure, DEV_Stop, DEV_Unconfigure, and DEV_Remove audit events to an audit class in the classes: stanza.

Edit the /etc/security/audit/config and assign the audit classes that has the DEV_Create, FILE_Mknod, DEV_Configure, DEV_Stop, DEV_Unconfigure and DEV_Remove events to the all users listed in the 'users:' stanza."
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37850r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22383'
  tag rid: 'SV-38858r1_rule'
  tag stig_id: 'GEN002825'
  tag gtitle: 'GEN002825'
  tag fix_id: 'F-33113r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
