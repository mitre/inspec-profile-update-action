control 'SV-235793' do
  title 'The Docker Enterprise self-signed certificates in Universal Control Plane (UCP) must be replaced with DoD trusted, signed certificates.'
  desc 'Docker Enterprise includes the following capabilities that are considered non-essential:

*NOTE: disabling these capabilities negatively affects the operation of Docker Trusted Registry (DTR) and should be disregarded when UCP and DTR are installed. The security capabilities provided by UCP and DTR offset any potential vulnerabilities associated with not disabling these essential capabilities the Engine provides.

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
  desc 'check', 'Check that UCP has been integrated with a trusted certificate authority (CA).

via UI:

In the UCP web console, navigate to "Admin Settings" | "Certificates" and click on the "Download UCP Server CA Certificate" link. Verify that the contents of the downloaded "ca.pem" file match that of the trusted CA certificate.

via CLI:

Linux: Execute the following command and verify the certificate chain in the output is valid and matches that of the trusted CA:

echo "" | openssl s_client -connect [ucp_url]:443 | openssl x509 -noout -text

If the certificate chain does not match the chain as defined by the System Security Plan, then this is a finding.'
  desc 'fix', %q(This fix only applies to the UCP component of Docker Enterprise.

Integrate UCP with a trusted certificate authority CA.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Certificates". Fill in (or click on the "Upload" links) the "CA Certificate" field with the contents of the external public CA certificate. Assuming the user generated a server certificate from that CA for UCP, also fill in the "Server Certificate" and "Private Key" fields with the contents of the public/private certificates respectively. The "Server Certificate" field must include both the UCP server certificate and any intermediate certificates. Click on the "Save" button.

If DTR was previously integrated with this UCP cluster, execute a "dtr reconfigure" command as a superuser on one of the UCP Manager nodes in the cluster to re-configure DTR with the updated UCP certificates.

via CLI:
Linux: As a superuser, execute the following commands on each UCP Manager node in the cluster and in the directory where keys and certificates are located:

Create a container that attaches to the same volume where certificates are stored:

docker create --name replace-certs -v ucp-controller-server-certs:/data busybox

Copy keys and certificates to the container's volumes:

docker cp cert.pem replace-certs:/data/cert.pem
docker cp ca.pem replace-certs:/data/ca.pem
docker cp key.pem replace-certs:/data/key.pem

Remove the container, since it is no longer needed:

docker rm replace-certs

Restart the container, since it is no longer needed:

docker rm replace-certs

Restart the ucp-controller container:

docker restart ucp-controller

If DTR was previously integrated with this UCP cluster, execute a "dtr reconfigure" command as a superuser on one of the UCP Manager nodes in the cluster to re-configure DTR with the updated UCP certificates.)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39012r627504_chk'
  tag severity: 'medium'
  tag gid: 'V-235793'
  tag rid: 'SV-235793r627506_rule'
  tag stig_id: 'DKER-EE-001870'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38975r627505_fix'
  tag 'documentable'
  tag legacy: ['SV-104757', 'V-95619']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
