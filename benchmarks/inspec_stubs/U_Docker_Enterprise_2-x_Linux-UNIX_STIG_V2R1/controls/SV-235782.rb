control 'SV-235782' do
  title 'A policy set using the built-in role-based access control (RBAC) capabilities in the Docker Trusted Registry (DTR) component of Docker Enterprise must be set.'
  desc 'Both the Universal Control Plane (UCP) and DTR components of Docker Enterprise leverage the same authentication and authorization backplane known as eNZi. eNZi provides UCP and DTR with role-based access control functionality to enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies. These policies are defined in the System Security Plan along with organization information, application user roles, system resources and access requirements. The eNZi backplane includes its own managed user database, and also allows for LDAP integration in UCP and DTR. While role-based access control mechanisms are provided regardless of whether or not LDAP integration is enabled, it is recommended to enable LDAP integration to better meet the requirements of this control.

'
  desc 'check', %q(This check only applies to the DTR component of Docker Enterprise.

Verify that the organization, team and user permissions in DTR are configured per the System Security Plan (SSP). Obtain and review SSP. Identify organization roles, teams and users.

via UI:

As a Docker EE Admin, navigate to "Organizations" and verify the list of organizations and teams within those organizations are setup per the SSP. Navigate to "Users" and verify that the list of users are assigned to appropriate organizations, teams and repositories per the SSP. 

If the organization, team and user permissions in DTR are not configured per the SSP, this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE admin, execute the following commands on a machine that can communicate with the DTR management console:

AUTHTOKEN=$(curl -kLsS -u <username>:<password> "https://[dtr_url]/auth/token" | jq -r .token)

Execute the following command to verify that the teams associated with an organization have access to the appropriate repositories per the System Security Plan:

curl -k -H "Authorization: Bearer $AUTHTOKEN" -X GET "https://[dtr_url]/api/v0/accounts/[org_name]/teams/[team_name]/repositoryAccess"

Execute the following commands on a machine that can communicate with the UCP management console to verify that the members of the team with access to these repositories is appropriate per the SSP:

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/accounts/[orgNameOrID]/teams/[teamNameOrID]/members

If the organization, team and user permissions in DTR are not configured per the SSP, this is a finding.)
  desc 'fix', %q(This fix only applies to the DTR component of Docker Enterprise.

Verify that the applied organization, team and user permissions in DTR are configured per the SSP.

via UI:

As a Docker EE Admin, navigate to "Organizations" and setup the list of organizations and teams within those organizations per the requirements set forth by the SSP. Navigate to "Users" and assign users to appropriate organizations, teams and repositories per the SSP. 

via CLI:

Linux (requires curl and jq): As a Docker EE admin, execute the following commands on a machine that can communicate with the DTR management console:

AUTHTOKEN=$(curl -kLsS -u <username>:<password> "https://[dtr_url]/auth/token" | jq -r .token)

Execute the following command to give teams in an organization access to the appropriate repositories per the System Security Plan:

curl -k -H "Authorization: Bearer $AUTHTOKEN" -X PUT "https://[dtr_url]/api/v0/repositories/[namespace]/[reponame]/teamAccess/[teamname]"

Execute the following commands on a machine that can communicate with the UCP management console to add/remove members to/from the team with access to these repositories as appropriate per the SSP:

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)

Add: curl -sk -H "Authorization: Bearer $AUTHTOKEN" -X PUT https://[ucp_url]/accounts/[orgNameOrID]/teams/[teamNameOrID]/members/[memberNameOrID]
Remove: curl -sk -H "Authorization: Bearer $AUTHTOKEN" -X DELETE https://[ucp_url]/accounts/[orgNameOrID]/teams/[teamNameOrID]/members/[memberNameOrID])
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39001r627471_chk'
  tag severity: 'medium'
  tag gid: 'V-235782'
  tag rid: 'SV-235782r627473_rule'
  tag stig_id: 'DKER-EE-001180'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-38964r627472_fix'
  tag satisfies: ['SRG-APP-000033', 'SRG-APP-000243', 'SRG-APP-000246', 'SRG-APP-000247', 'SRG-APP-000267', 'SRG-APP-000328', 'SRG-APP-000340', 'SRG-APP-000342', 'SRG-APP-000378', 'SRG-APP-000380', 'SRG-APP-000384', 'SRG-APP-000038', 'SRG-APP-000039', 'SRG-APP-000080', 'SRG-APP-000311', 'SRG-APP-000313', 'SRG-APP-000314']
  tag 'documentable'
  tag legacy: ['SV-104707', 'V-95357']
  tag cci: ['CCI-000166', 'CCI-000213', 'CCI-001414', 'CCI-001314', 'CCI-001368', 'CCI-001095', 'CCI-001090', 'CCI-001094', 'CCI-001764', 'CCI-001812', 'CCI-001813', 'CCI-002263', 'CCI-002264', 'CCI-002235', 'CCI-002262', 'CCI-002233', 'CCI-002165']
  tag nist: ['AU-10', 'AC-3', 'AC-4', 'SI-11 b', 'AC-4', 'SC-5 (2)', 'SC-4', 'SC-5 (1)', 'CM-7 (2)', 'CM-11 (2)', 'CM-5 (1) (a)', 'AC-16 a', 'AC-16 a', 'AC-6 (10)', 'AC-16 a', 'AC-6 (8)', 'AC-3 (4)']
end
