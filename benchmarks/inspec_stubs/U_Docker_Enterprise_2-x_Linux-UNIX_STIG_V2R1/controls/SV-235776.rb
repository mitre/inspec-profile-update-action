control 'SV-235776' do
  title 'TCP socket binding for all Docker Engine - Enterprise nodes in a Universal Control Plane (UCP) cluster must be disabled.'
  desc 'The UCP component of Docker Enterprise configures and leverages Swarm Mode for node-to-node cluster communication. Swarm Mode is built in to Docker Engine - Enterprise and uses TLS 1.2 at a minimum for encrypting communications. Under the hood, Swarm Mode includes an embedded public key infrastructure (PKI) system. When a UCP cluster is initialized, the first node in the cluster designates itself as a manager node. That node subsequently generates a new root Certificate Authority (CA) along with a key pair, which are used to secure communications with other UCP nodes that join the swarm. One can also specify his/her own externally-generated root CA upon initialization of a UCP cluster. The manager node also generates two tokens to use when joining additional nodes to the cluster: one worker token and one manager token. Each token includes the digest of the root CA’s certificate and a randomly generated secret. When a node joins the cluster, the joining node uses the digest to validate the root CA certificate from the remote manager. The remote manager uses the secret to ensure the joining node is an approved node. Each time a new node joins the cluster, the manager issues a certificate to the node. The certificate contains a randomly generated node ID to identify the node under the certificate common name (CN) and the role under the organizational unit (OU). The node ID serves as the cryptographically secure node identity for the lifetime of the node in the current swarm. In this mutual TLS architecture, all nodes encrypt communications using a minimum of TLS 1.2, thereby satisfying the requirements of this control. This information can also be referenced at https://docs.docker.com/engine/swarm/how-swarm-mode-works/pki/ and https://docs.docker.com/ee/ucp/ucp-architecture/.

By itself, Docker Engine - Enterprise is configured by default to listen for API requests via a UNIX domain socket (or IPC socket) created at /var/run/docker.sock on supported Linux distributions and via a named pipe at npipe:////./pipe/docker_engine on Windows Server 2016 and newer. Docker Engine - Enterprise can also be configured to listen for API requests via additional socket types, including both TCP and FD (only on supported systemd-based Linux distributions). If configured to listen for API requests via the TCP socket type over TCP port 2376 and with the daemon flags and SSL certificates, then, at a minimum, TLS 1.2 is used for encryption; therefore this control is applicable and is inherently met in this configuration. If configured to listen for API requests via the TCP socket type, but without TLS verification and certifications, then the instance remains vulnerable and is not properly configured to meet the requirements of this control. If configured to listen for API requests via the FD socket type, then this control is not applicable. More information can be found at https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option. The TCP socket binding should be disabled when running Engine as part of a UCP cluster.

'
  desc 'check', 'This check only applies to the Docker Engine - Enterprise component of Docker Enterprise.

via CLI:

Linux: Verify the daemon has not been started with the "-H TCP://[host]" argument by running the following command:

ps -ef | grep dockerd

If -H UNIX://, this is not a finding.

If the "-H TCP://[host]" argument appears in the output, then this is a finding.'
  desc 'fix', 'This fix only applies to Docker Engine - Enterprise nodes that are part of a UCP cluster.

Apply this fix to every node in the cluster.

(Linux) Execute the following command to open an override file for docker.service:

sudo systemctl edit docker.service

Remove any "-H" host daemon flags from the "ExecStart=/usr/bin/dockerd" line in the override file.

Save the file and reload the config with the following command:

sudo systemctl daemon-reload

Restart Docker with the following command:

sudo systemctl restart docker.service'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-38995r627453_chk'
  tag severity: 'medium'
  tag gid: 'V-235776'
  tag rid: 'SV-235776r627455_rule'
  tag stig_id: 'DKER-EE-001050'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-38958r627454_fix'
  tag satisfies: ['SRG-APP-000014', 'SRG-APP-000141', 'SRG-APP-000219', 'SRG-APP-000383', 'SRG-APP-000439', 'SRG-APP-000440', 'SRG-APP-000441', 'SRG-APP-000442', 'SRG-APP-000142']
  tag 'documentable'
  tag legacy: ['SV-104695', 'V-94865']
  tag cci: ['CCI-000068', 'CCI-000381', 'CCI-000382', 'CCI-001184', 'CCI-001762', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'CM-7 a', 'CM-7 b', 'SC-23', 'CM-7 (1) (b)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']
end
