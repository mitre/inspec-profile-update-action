control 'SV-40138' do
  title 'The audit system must be configured to audit all administrative, privileged, and security actions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Check the auditing configuration of the system.
# more /etc/security/audit/events

Verify the following events are configured.
ACCT_Disable, ACCT_Enable, AUD_it, BACKUP_Export, DEV_Change, DEV_Configure, DEV_Create, FILE_Chpriv, FILE_Fchpriv, FILE_Mknod, FILE_Owner, FS_Chroot, FS_Mount, FS_Umount, PASSWORD_Check, PROC_Adjtime, PROC_Kill, PROC_Privilege, PROC_Setpgid, PROC_SetUserIDs, RESTORE_Import, TCBCK_Delete, USER_Change, USER_Create, USER_Reboot, USER_Remove, and USER_SetEnv

If any of these events are missing from the configuration, this is a finding.

Check the ACCT_Disable, ACCT_Enable, AUD_it, BACKUP_Export, DEV_Change, DEV_Configure, DEV_Create, FILE_Chpriv, FILE_Fchpriv, FILE_Mknod, FILE_Owner, FS_Chroot, FS_Mount, FS_Umount, PASSWORD_Check, PROC_Adjtime, PROC_Kill, PROC_Privilege, PROC_Setpgid, PROC_SetUserIDs, RESTORE_Import, TCBCK_Delete, USER_Change, USER_Create, USER_Reboot, USER_Remove, and USER_SetEnv audit events are defined in the audit classes' stanza 'classes:' of the /etc/security/audit/config file.

#more  /etc/security/audit/config
Make note of the audit class(es) that the ACCT_Disable, ACCT_Enable, AUD_it, BACKUP_Export, DEV_Change, DEV_Configure, DEV_Create, FILE_Chpriv, FILE_Fchpriv, FILE_Mknod, FILE_Owner, FS_Chroot, FS_Mount, FS_Umount, PASSWORD_Check, PROC_Adjtime, PROC_Kill, PROC_Privilege, PROC_Setpgid, PROC_SetUserIDs, RESTORE_Import, TCBCK_Delete, USER_Change, USER_Create, USER_Reboot, USER_Remove, and USER_SetEnv events are associated with.
If the ACCT_Disable, ACCT_Enable, AUD_it, BACKUP_Export, DEV_Change, DEV_Configure, DEV_Create, FILE_Chpriv, FILE_Fchpriv, FILE_Mknod, FILE_Owner, FS_Chroot, FS_Mount, FS_Umount, PASSWORD_Check, PROC_Adjtime, PROC_Kill, PROC_Privilege, PROC_Setpgid, PROC_SetUserIDs, RESTORE_Import, TCBCK_Delete, USER_Change, USER_Create, USER_Reboot, USER_Remove, and USER_SetEnv events are not associated with any audit classes in the classes: stanza, this is a finding.

Verify the audit class is associated with the default user and all other user ids listed in the users: stanza of the /etc/security/audit/config file.
#more /etc/security/audit/config
If the class(es) that the ACCT_Disable, ACCT_Enable, AUD_it, BACKUP_Export, DEV_Change, DEV_Configure, DEV_Create, FILE_Chpriv, FILE_Fchpriv, FILE_Mknod, FILE_Owner, FS_Chroot, FS_Mount, FS_Umount, PASSWORD_Check, PROC_Adjtime,PROC_Kill, PROC_Privilege, PROC_Setpgid, PROC_SetUserIds, RESTORE_Import, TCBCK_Delete, USER_Change, USER_Create, USER_Reboot, USER_Remove, and USER_SetEnv events are not associated with the default user and all the system users in the 'users:' stanza,  this is a finding."
  desc 'fix', 'Edit /etc/security/audit/events and add the following events to the list of audited events:
ACCT_Disable, ACCT_Enable, AUD_it, BACKUP_Export, DEV_Change, DEV_Configure, DEV_Create, FILE_Chpriv, FILE_Fchpriv, FILE_Mknod, FILE_Owner, FS_Chroot, FS_Mount, FS_Umount, PASSWORD_Check, PROC_Adjtime, PROC_Kill, PROC_Privilege, PROC_Setpgid, PROC_SetUserIDs, RESTORE_Import, TCBCK_Delete, USER_Change, USER_Create, USER_Reboot, USER_Remove, and USER_SetEnv.  
 
Edit /etc/security/audit/config and add the ACCT_Disable, ACCT_Enable, AUD_it, BACKUP_Export, DEV_Change, DEV_Configure, DEV_Create, FILE_Chpriv, FILE_Fchpriv, FILE_Mknod, FILE_Owner, FS_Chroot, FS_Mount, FS_Umount, PASSWORD_Check, PROC_Adjtime, PROC_Kill, PROC_Privilege, PROC_Setpgid, PROC_SetUserIDs, RESTORE_Import, TCBCK_Delete, USER_Change, USER_Create, USER_Reboot, USER_Remove, and USER_SetEnv audit events to an audit class in the classes: stanza.

Edit the /etc/security/audit/config and assign the audit classes with the ACCT_Disable, ACCT_Enable, AUD_it, BACKUP_Export, DEV_Change, DEV_Configure, DEV_Create, FILE_Chpriv, FILE_Fchpriv, FILE_Mknod, FILE_Owner, FS_Chroot, FS_Mount, FS_Umount, PASSWORD_Check, PROC_Adjtime, PROC_Kill, PROC_Privilege, PROC_Setpgid, PROC_SetUserIDs, RESTORE_Import, TCBCK_Delete, USER_Change, USER_Create, USER_Reboot, USER_Remove, and USER_SetEnv events to the all users listed in the users: stanza.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28415r1_chk'
  tag severity: 'medium'
  tag gid: 'V-816'
  tag rid: 'SV-40138r1_rule'
  tag stig_id: 'GEN002760'
  tag gtitle: 'GEN002760'
  tag fix_id: 'F-24542r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000347']
  tag nist: ['CM-5 (1)']
end
