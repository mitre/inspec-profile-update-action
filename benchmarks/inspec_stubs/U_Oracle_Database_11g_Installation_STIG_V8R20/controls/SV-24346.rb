control 'SV-24346' do
  title 'Only necessary privileges to the host system should be granted to DBA OS accounts.'
  desc 'Database administration accounts are frequently granted more permissions to the local host system than are necessary. This allows inadvertent or malicious changes to the host operating system.'
  desc 'check', 'Review host system privileges assigned to the Oracle DBA group and all individual Oracle DBA accounts.

NOTE: do not include the Oracle software installation account in any results for this check.

For UNIX systems (as root):
  cat /etc/group | grep -i dba
  groups root

If "root" is returned in the first list, this is a Finding.

If any accounts listed in the first list are also listed in the second list, this is a Finding.

Investigate any user account group memberships other than DBA or root groups that are returned by the following command (also as root):

  groups [dba user account]

Replace [dba user account] with the user account name of each DBA account.

If individual DBA accounts are assigned to groups that grant access or privileges for purposes other than DBA responsibilities, this is a Finding.

For Windows Systems (click or select):
  Start / Settings / Control Panel / Administrative Tools / Computer Management / Local Users and Groups / Groups / ORA_DBA
  Start / Settings / Control Panel / Administrative Tools / Computer Management / Local Users and Groups / Groups / ORA_[SID]_DBA (if present)

NOTE: Users assigned DBA privileges on a Windows host are granted membership in the ORA_DBA and/or ORA_[SID]_DBA groups. The ORA_DBA group grants DBA privileges to any database on the system. The ORA_[SID]_DBA groups grant DBA privileges to specific Oracle instances only.

Make a note of each user listed. For each user (click or select):
  Start / Settings / Control Panel / Administrative Tools / Computer Management / Local Users and Groups / Users / [DBA user name] / Member of

If DBA users belong to any groups other than DBA groups and the Windows Users group, this is a Finding.

Examine User Rights assigned to DBA groups or group members:
  Start / Settings / Control Panel / Administrative Tools / Local Security Policy / Security Settings / Local Policies / User Rights Assignments

If any User Rights are assigned directly to the DBA group(s) or DBA user accounts, this is a Finding.'
  desc 'fix', 'Revoke all host system privileges from the DBA group accounts and DBA user accounts not required for DBMS administration.

Revoke all OS group memberships that assign excessive privileges to the DBA group accounts and DBA user accounts.

Remove any directly applied permissions or user rights from the DBA group accounts and DBA user accounts.

You should document all DBA group accounts and individual DBA account assigned privileges in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-28571r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6756'
  tag rid: 'SV-24346r1_rule'
  tag stig_id: 'DG0005-ORACLE11'
  tag gtitle: 'DBMS administration OS accounts'
  tag fix_id: 'F-24656r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Database Administrator']
end
