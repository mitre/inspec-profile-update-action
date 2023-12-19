control 'SV-255325' do
  title 'Azure SQL Database must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events. 
 
Suppression of auditing could permit an adversary to evade detection. 
 
Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Obtain the list of approved audit maintainers from the system documentation.

If any role memberships are not documented and authorized, this is a finding.	

Review the Azure roles and individual users, all of which enable the ability to create and maintain audits.

To review the Azure roles and users, navigate to the Azure Portal and review the Azure Server controlling the Azure SQL Database.
1. Select "Access Control (IAM)".
2. Select "Role assignments" and review the roles assigned to each user.
3. Select "Roles", and then select "View" under the Details column for each role.

Any roles or users with Write permissions to the auditing policy must be documented.

This may include but is not limited to the Owner, Contributor, and Administrator roles.

If any of the roles or users have permissions that are not documented, or the documented audit maintainers do not have permissions, this is a finding.'
  desc 'fix', 'Create an Azure role specifically for audit maintainers, and give it write permissions to audit related permissions in the portal, without granting it unnecessary permissions. The role name used here is an example; other names may be used:

Audit permissions are managed through the Azure Portal, PowerShell, CLI or REST API (not managed using TSQL in Azure SQL Database).'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58998r877274_chk'
  tag severity: 'medium'
  tag gid: 'V-255325'
  tag rid: 'SV-255325r877275_rule'
  tag stig_id: 'ASQL-00-004400'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-58942r877275_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
