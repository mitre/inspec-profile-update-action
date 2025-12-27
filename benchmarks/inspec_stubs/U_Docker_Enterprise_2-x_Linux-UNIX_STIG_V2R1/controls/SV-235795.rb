control 'SV-235795' do
  title 'The option in Universal Control Plane (UCP) allowing users and administrators to schedule containers on all nodes, including UCP managers and Docker Trusted Registry (DTR) nodes must be disabled in Docker Enterprise.'
  desc 'Docker Enterprise includes the following capabilities that are considered non-essential:

*NOTE: disabling these capabilities negatively affects the operation of UCP and DTR and should be disregarded when UCP and DTR are installed. The security capabilities provided by UCP and DTR offset any potential vulnerabilities associated with not disabling these essential capabilities the Engine provides.

(Docker Engine - Enterprise: Standalone) - The majority of these items were originally identified as part of the CIS Docker Benchmark, which as of the CIS Docker Benchmark v1.2.0, are still applicable to Docker Engine - Enterprise 18.09
- inter-container communication (icc)* (CIS Docker Benchmark Recommendation 2.1)
- insecure registry communication (CIS Docker Benchmark Recommendation 2.4)
- AUFS storage driver (applicable on Linux only) (CIS Docker Benchmark Recommendation 2.5)
- listening on the TCP Daemon socket
- userland proxy for loopback traffic* (CIS Docker Benchmark Recommendation 2.15)
- experimental features (CIS Docker Benchmark Recommendation 2.17)
- Swarm Mode (CIS Docker Benchmark Recommendation 7.1)

(Docker Engine - Enterprise: As part of a UCP cluster)
- insecure registry communication (CIS Docker Benchmark Recommendation 2.4)
- AUFS storage driver (applicable on Linux only) (CIS Docker Benchmark Recommendation 2.5)
- listening on the TCP Daemon socket
- experimental features (CIS Docker Benchmark Recommendation 2.17)

(UCP)
- Managed user database
- self-signed certificates
- periodic usage reporting and API tracking
- allow users and administrators to schedule containers on all nodes, including UCP managers and DTR nodes

(DTR)
- periodic data usage/analytics reporting
- create repository on push
- self-signed certificates'
  desc 'check', %q(Verify that admins and users are not allowed to schedule containers on manager nodes and DTR nodes.

via UI:

As a Docker EE Admin, navigate to "Admin Settings" | "Scheduler" in the UCP management console. Verify that the "Allow administrators to deploy containers on UCP managers or nodes running DTR" and "Allow users to schedule on all nodes, including UCP managers and DTR nodes" options are both unchecked.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands on a machine that can communicate with the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml

Look for the "enable_admin_ucp_scheduling" entry under the "[scheduling_configuration]" section in the output, and verify that it is set to "false".
If "enable_admin_ucp_scheduling" is not set to "false", this is a finding.

Execute the following command:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/collectionGrants?subjectType=all&expandUser=true&showPaths=true

Ensure a Grant for the "Scheduler" role against the "/" collection for the "docker-datacenter" organization does not exist in the output. If it does, then this is a finding.)
  desc 'fix', %q(This fix only applies to the UCP component of Docker Enterprise.

Prevent admins and users from being able to schedule containers on manager nodes and DTR nodes.

via UI:

As a Docker EE Admin, navigate to "Admin Settings" | "Scheduler" in the UCP management console. Uncheck both the "Allow administrators to deploy containers on UCP managers or nodes running DTR" and "Allow users to schedule on all nodes, including UCP managers and DTR nodes" options. Click "Save".

via CLI:

Linux: As a Docker EE Admin, execute the following commands on a machine that can communicate with the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator:

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml > ucp-config.toml

Open the "ucp-config.toml" file, set the "enable_admin_ucp_scheduling" entry under the "[scheduling_configuration]" section to "false". Save the file.

Execute the following commands to update UCP with the new configuration:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" --upload-file ucp-config.toml https://[ucp_url]/api/ucp/config-toml

Delete the Grant for the "Scheduler" role against the "/" collection for the "docker-datacenter" organization by executing the following command:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" -X DELETE https://[ucp_url]/collectionGrants/[subjectID]/[objectID]/[roleID])
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39014r627510_chk'
  tag severity: 'medium'
  tag gid: 'V-235795'
  tag rid: 'SV-235795r627512_rule'
  tag stig_id: 'DKER-EE-001890'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38977r627511_fix'
  tag 'documentable'
  tag legacy: ['SV-104761', 'V-95623']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
