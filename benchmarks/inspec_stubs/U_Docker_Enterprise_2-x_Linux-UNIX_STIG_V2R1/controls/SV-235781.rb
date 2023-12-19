control 'SV-235781' do
  title 'A policy set using the built-in role-based access control (RBAC) capabilities in the Universal Control Plane (UCP) component of Docker Enterprise must be configured.'
  desc 'Both the UCP and Docker Trusted Registry (DTR) components of Docker Enterprise leverage the same authentication and authorization backplane known as eNZi. eNZi provides UCP and DTR with role-based access control functionality to enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies. The eNZi backplane includes its own managed user database, and also allows for LDAP integration in UCP and DTR. While role-based access control mechanisms are provided regardless of whether or not LDAP integration is enabled, it is recommended to enable LDAP integration to better meet the requirements of this control.

'
  desc 'check', %q(This check only applies to the UCP component of Docker Enterprise. 

Verify that the applied RBAC policy sets in UCP are configured per the requirements set forth by the System Security Plan (SSP).

via UI:

As a Docker EE Admin, navigate to "Access Control" | "Grants" in the UCP web console. Verify that all grants and cluster role bindings applied to Swarm are configured per the requirements set forth by the System Security Plan (SSP).

If the applied RBAC policy sets in UCP are not configured per the requirements set forth by the SSP, then this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands on a machine that can communicate with the UCP management console:

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)

curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/collectionGrants?subjectType=all&expandUser=true&showPaths=true

Verify that all grants applied to Swarm in the API response are configured per the requirements set forth by the System Security Plan (SSP).

If the applied RBAC policy sets in UCP are not configured per the requirements set forth by the SSP, then this is a finding.)
  desc 'fix', %q(This fix only applies to the UCP component of Docker Enterprise.

Apply RBAC policy sets in UCP per the requirements set forth by the SSP.

via UI:

As a Docker EE Admin, navigate to "Access Control" | "Grants" in the UCP web console. Create grants and cluster role bindings for Swarm per the requirements set forth by the SSP.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands on a machine that can communicate with the UCP management console:

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)

Create grants for Swarm for applicable subjects, objects and roles using the following command:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" -X PUT https://[ucp_url]/collectionGrants/[subjectID]/[objectID]/[roleID])
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39000r627468_chk'
  tag severity: 'medium'
  tag gid: 'V-235781'
  tag rid: 'SV-235781r627470_rule'
  tag stig_id: 'DKER-EE-001170'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-38963r627469_fix'
  tag satisfies: ['SRG-APP-000033', 'SRG-APP-000038', 'SRG-APP-000039', 'SRG-APP-000080', 'SRG-APP-000243', 'SRG-APP-000246', 'SRG-APP-000247', 'SRG-APP-000267', 'SRG-APP-000311', 'SRG-APP-000313', 'SRG-APP-000314', 'SRG-APP-000328', 'SRG-APP-000340', 'SRG-APP-000342', 'SRG-APP-000378', 'SRG-APP-000380', 'SRG-APP-000384']
  tag 'documentable'
  tag legacy: ['SV-104705', 'V-95355']
  tag cci: ['CCI-001812', 'CCI-001813', 'CCI-001764', 'CCI-001090', 'CCI-001094', 'CCI-001095', 'CCI-001314', 'CCI-001368', 'CCI-001414', 'CCI-000213', 'CCI-000166', 'CCI-002165', 'CCI-002233', 'CCI-002235', 'CCI-002262', 'CCI-002263', 'CCI-002264']
  tag nist: ['CM-11 (2)', 'CM-5 (1) (a)', 'CM-7 (2)', 'SC-4', 'SC-5 (1)', 'SC-5 (2)', 'SI-11 b', 'AC-4', 'AC-4', 'AC-3', 'AU-10', 'AC-3 (4)', 'AC-6 (8)', 'AC-6 (10)', 'AC-16 a', 'AC-16 a', 'AC-16 a']
end
