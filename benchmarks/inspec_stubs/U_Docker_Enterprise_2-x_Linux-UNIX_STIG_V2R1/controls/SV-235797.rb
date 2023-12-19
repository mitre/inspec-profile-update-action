control 'SV-235797' do
  title 'Periodic data usage and analytics reporting in Universal Control Plane (UCP) must be disabled in Docker Enterprise.'
  desc 'Docker Enterprise includes the following capabilities that are considered non-essential:

*NOTE: disabling these capabilities negatively affects the operation of UCP and Docker Trusted Registry (DTR) and should be disregarded when UCP and DTR are installed. The security capabilities provided by UCP and DTR offset any potential vulnerabilities associated with not disabling these essential capabilities the Engine provides.

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
  desc 'check', %q(This check only applies to the UCP component of Docker Enterprise.

Verify that usage and API analytics tracking is disabled in UCP:

via UI:

As a Docker EE Admin, navigate to "Admin Settings" | "Usage" in the UCP management console. Verify that the "Enable hourly usage reporting" and "Enable API and UI tracking" options are both unchecked.

If either box is checked, this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands on a machine that can communicate with the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.
AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml

Look for the "disable_usageinfo" and "disable_tracking" entries under the "[tracking_configuration]" section in the output, and verify that they are both set to "true". If they are not, then this is a finding.)
  desc 'fix', %q(This fix only applies to the UCP component of Docker Enterprise.

Disable usage and API analytics tracking in UCP:

via UI:

As a Docker EE Admin, navigate to "Admin Settings" | "Usage" in the UCP management console. Uncheck both the "Enable hourly usage reporting" and "Enable API and UI tracking" options. Click "Save".

via CLI:

Linux: As a Docker EE Admin, execute the following commands on a machine that can communicate with the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator:

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml > ucp-config.toml

Open the "ucp-config.toml" file. Set both the "disable_usageinfo" and "disable_tracking" entries under the "[tracking_configuration]" section to "true". Save the file.

Execute the following commands to update UCP with the new configuration:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" --upload-file ucp-config.toml https://[ucp_url]/api/ucp/config-toml)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39016r627516_chk'
  tag severity: 'medium'
  tag gid: 'V-235797'
  tag rid: 'SV-235797r627518_rule'
  tag stig_id: 'DKER-EE-001910'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38979r627517_fix'
  tag 'documentable'
  tag legacy: ['SV-104765', 'V-95627']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
