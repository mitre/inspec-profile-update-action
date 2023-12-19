control 'SV-235796' do
  title 'The Create repository on push option in Docker Trusted Registry (DTR) must be disabled in Docker Enterprise.'
  desc 'Docker Enterprise includes the following capabilities that are considered non-essential:

*NOTE: disabling these capabilities negatively affects the operation of Universal Control Plane (UCP) and DTR and should be disregarded when UCP and DTR are installed. The security capabilities provided by UCP and DTR offset any potential vulnerabilities associated with not disabling these essential capabilities the Engine provides.

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
  desc 'check', 'This check only applies to the DTR component of Docker Enterprise.

Verify that the "Create repository on push" option is disabled in DTR:

via UI:

As a Docker EE Admin, navigate to "System" | "General" in the DTR management console. Verify that the "Create repository on push" slider is turned off.

via CLI:

Linux (requires curl and jq):

AUTHTOKEN=$(curl -sk -u <username>:<password> "https://[dtr_url]/auth/token" | jq -r .token)
curl -k -H "Authorization: Bearer $AUTHTOKEN"" -X GET ""https://[dtr_url]/api/v0/meta/settings"

Look for the "createRepositoryOnPush" field in the output and verify that it is set to "false". If it is not, then this is a finding.'
  desc 'fix', %q(This fix only applies to the DTR component of Docker Enterprise.

Disable the "Create repository on push" option in DTR:

via UI:

As a Docker EE Admin, navigate to "System" | "General" in the DTR management console. Click the "Create repository on push" slider to disable this capability.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity to the DTR management console:

AUTHTOKEN=$(curl -sk -u <username>:<password> "https://[dtr_url]/auth/token" | jq -r .token)
curl -k -H "Authorization: Bearer $AUTHTOKEN" -X POST -d '{"createRepositoryOnPush":true}' -H 'Content-Type: application/json' "https://[dtr_url]/api/v0/meta/settings")
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39015r627513_chk'
  tag severity: 'medium'
  tag gid: 'V-235796'
  tag rid: 'SV-235796r627515_rule'
  tag stig_id: 'DKER-EE-001900'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38978r627514_fix'
  tag 'documentable'
  tag legacy: ['SV-104763', 'V-95625']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
