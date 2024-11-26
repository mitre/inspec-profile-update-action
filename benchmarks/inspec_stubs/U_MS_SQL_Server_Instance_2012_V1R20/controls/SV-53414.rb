control 'SV-53414' do
  title 'DBA OS or domain accounts must be granted only those host system privileges necessary for the administration of SQL Server.'
  desc 'SQL Server DBAs, if assigned excessive OS privileges, could perform actions that could endanger the information system or hide evidence of malicious activity.

This requirement is intended to limit exposure due to operating from within a privileged account or role. The check and fix are based on the assumption that Role-Based Access Control (RBAC) is in effect, as mandated by other STIG requirements.  They further assume that, as mandated elsewhere, the privileged accounts discussed here are distinct from the accounts used by the same people when not performing privileged functions.'
  desc 'check', "From the system security documentation, obtain the list of SQL Server DBA accounts, the OS/domain Group(s) representing those DBAs' job role(s), and the OS permissions required by that/those role(s).


To review local accounts and groups:

Log on to the Windows server hosting SQL Server, using an account with administrator privileges.

From a command prompt opened as administrator, type gpedit.msc, and press [ENTER].  In Group Policy Editor, navigate to Local Computer Policy > Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment.  Scan the list to determine which privileges are assigned to the Group(s) representing the SQL Server DBA job role(s).  If any privileges are assigned that are not required by these roles, this is a finding.

From the command prompt, type lusrmgr.msc, and press [ENTER].  In the Local Users and Groups console, navigate to Users.  Right-click each DBA user. Click Properties. Click the 'Member of' tab.  If any parent groups are listed that are not specific to DBA roles, this is a finding.

In the Local Users and Groups console, navigate to Groups.  Right-click each DBA Group.  Click Properties.  Review the list of group members.  If any account that does not represent a DBA is listed, this is a finding.


To review domain-level accounts and groups:

Log on to a domain controller with the necessary privileges.

Open Active Directory Users and Computers (available from menus or run dsa.msc)

Determine the location of the accounts or groups to be reviewed.  The default is the Users container, but they could have been created or moved to an Organizational Unit (OU) that is domain specific.

Right-click each DBA user. Click Properties. Click the 'Member of' tab.  If any parent groups are listed that are not specific to DBA roles, this is a finding.

Right-click each DBA Group.  Click Properties.  Select the 'Members' tab. Review the list of group members.  If any account that does not represent a DBA is listed, this is a finding."
  desc 'fix', 'Remove any unnecessary privileges and any unauthorized members from the Group(s) representing DBAs.

Remove any unnecessary Group memberships from the user accounts representing DBAs.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47656r7_chk'
  tag severity: 'medium'
  tag gid: 'V-41039'
  tag rid: 'SV-53414r4_rule'
  tag stig_id: 'SQL2-00-010000'
  tag gtitle: 'SRG-APP-000063-DB-000021'
  tag fix_id: 'F-46338r4_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
