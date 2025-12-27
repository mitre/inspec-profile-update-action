control 'SV-235871' do
  title 'Docker Enterprise Universal Control Plane (UCP) must be integrated with a trusted certificate authority (CA).'
  desc 'When integrating the UCP and Docker Trusted Registry (DTR) management consoles with an external, trusted certificate authority (CA), both UCP and DTR will validate these certificate chains per the requirements set forth by the System Security Plan (SSP).

UCP establishes mutual TLS authentication for all Engine - Enterprise nodes in a cluster using a built-in certificate authority which inherently meets the requirements of this control. This is described below.

The UCP component of Docker Enterprise includes a built-in public key infrastructure (PKI) system. When a UCP cluster is initialized, the first node designates itself as a manager node. That node subsequently generates a new root CA along with a key pair, which are used to secure communications with other UCP manager and worker nodes that are joined to the cluster. One can also specify his/her own externally-generated root CA upon initialization of a UCP cluster. The manager node also generates two tokens to use when joining additional nodes to the cluster: one worker token and one manager token. Each token includes the digest of the root CA’s certificate and a randomly generated secret. When a node joins the cluster, the joining node uses the digest to validate the root CA certificate from the remote manager. The remote manager uses the secret to ensure the joining node is an approved node. Each time a new node joins the cluster, the manager issues a certificate to the node. The certificate contains a randomly generated node ID to identify the node under the certificate common name (CN) and the role under the organizational unit (OU). The node ID serves as the cryptographically secure node identity for the lifetime of the node in the current UCP cluster. In this mutual TLS architecture, all nodes encrypt communications using a minimum of TLS 1.2. This information can also be referenced at https://docs.docker.com/engine/swarm/how-swarm-mode-works/pki/.'
  desc 'check', %q(This check only applies to the UCP component of Docker Enterprise.

Check that UCP has been integrated with a trusted CA.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Certificates" and click on the "Download UCP Server CA Certificate" link. Verify that the contents of the downloaded "ca.pem" file match that of the user's trusted CA certificate.

If the UCP certificate is not signed by a trusted DoD CA this is a finding.

via CLI:

Linux: Execute the following command and verify the certificate chain in the output is valid and matches that of the trusted CA:

echo "" | openssl s_client -connect [ucp_url]:443 | openssl x509 -noout -text

If the UCP certificate is not signed by a trusted DoD CA this is a finding.)
  desc 'fix', %q(This fix only applies to the UCP component of Docker Enterprise.

Integrate UCP with a trusted CA.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Certificates". Fill in (or click on the "Upload" links) the "CA Certificate" field with the contents of the trusted CA certificate. Assuming the user generated a server certificate from that CA for UCP, also fill in the "Server Certificate" and "Private Key" fields with the contents of the public/private certificates respectively. The "Server Certificate" field must include both the UCP server certificate and any intermediate certificates. Click on the "Save" button.

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

Restart the ucp-controller container:

docker restart ucp-controller

If DTR was previously integrated with this UCP cluster, execute a "dtr reconfigure" command as a superuser on one of the UCP Manager nodes in the cluster to re-configure DTR with the updated UCP certificates.)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39090r627738_chk'
  tag severity: 'medium'
  tag gid: 'V-235871'
  tag rid: 'SV-235871r627740_rule'
  tag stig_id: 'DKER-EE-006190'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-39053r627739_fix'
  tag 'documentable'
  tag legacy: ['SV-104917', 'V-95779']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
