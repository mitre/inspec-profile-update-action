control 'SV-93709' do
  title 'The BlackBerry Enterprise Mobility Server (BEMS) must protect log information from any type of unauthorized read access.'
  desc 'If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to his or her advantage.

Application servers contain admin interfaces that allow reading and manipulation of log records. Therefore, these interfaces should not allow unfettered access to those records. Application servers also write log data to log files which are stored on the OS, so appropriate file permissions must also be used to restrict access.

Log information includes all information (e.g., log records, log settings, transaction logs, and log reports) needed to successfully log information system activity. Application servers must protect log information from unauthorized read access.'
  desc 'check', 'Verify BEMS has been configured with the following administrator groups/roles, each group/role has required permissions, and at least one user has been assigned to each Administrator group/role: Server primary administrator, auditor.

Procedure for Server Primary Administrator:
1. In the BEMS Dashboard, under "BEMS System Settings", click "BEMS Configuration".
2. Click "Dashboard Administrators".
3. Confirm the Administrator role for the primary server administrator has been assigned the dashboard role of Admin.
4. Verify in AD at least one member has been assigned to the BEMS administrator group. (Note: Actual group name may be different.)

Procedure for Auditor:
1. Verify in AD an auditor group has been set up with at least one member.
2. Browse to the log repository.
3. Right-click on the folder.
4. Select "Properties".
5. Select the "Security" tab.
6. Confirm the auditor security group is listed.

If required administrator roles have not been set up on BEMS and at least one user has not been assigned to each role, this is a finding.'
  desc 'fix', 'Configure BEMS to have at least one user in the following Administrator roles: Server primary administrator, auditor.

1. In the BEMS Dashboard, under "BEMS System Settings", click "BEMS Configuration".
2. Click "Dashboard Administrators".
3. Click "Add Group".
4. In the "Active Directory Security Group" field, type the name of the Microsoft Active Directory security group.
5. Click "Save".
6. Repeat steps 3 to 5 to add additional security groups.
7. For the server primary administrator, the default role of Admin meets the required roles and no additional configuration is needed.
8. For the Auditor role, complete the following steps:
  - In active directory, create a domain auditor group and assign personnel designated as auditors to that group.
  - Browse to the log repository.
  - Right-click on the folder.
  - Select "Properties".
  - Select the "Security" tab.
  - Click "Edit".
  - Click "Add".
  - Type in name of the user group.
  - Confirm that only the necessary groups have rights to the folder (CREATOR OWNER, SYSTEM, Administrators, Auditors).
  - Set proper permissions for auditors (Read, List folder contents, Read & Execute).'
  impact 0.5
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78591r1_chk'
  tag severity: 'medium'
  tag gid: 'V-79003'
  tag rid: 'SV-93709r1_rule'
  tag stig_id: 'BEMS-00-002600'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag fix_id: 'F-85753r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
