control 'SV-235779' do
  title 'The host operating systems auditing policies for the Docker Engine - Enterprise component of Docker Enterprise must be set.'
  desc %q(The Universal Control Plane (UCP) and Docker Trusted Registry (DTR) components of Docker Enterprise provide audit record generation capabilities. Audit logs capture all HTTP actions for the following endpoints: Kubernetes API, Swarm API and UCP API. The following UCP API endpoints are excluded from audit logging (where "*" designates a wildcard of exclusions): "/_ping", "/ca", "/auth", "/trustedregistryca", "/kubeauth", "/metrics", "/info", "/version*", "/debug", "/openid_keys", "/apidocs", "kubernetesdocs" and "/manage". Audit log verbosity can be set to one of the following levels: "none", "metadata", or "request". To meet the requirements of this control, the "request" verbosity level must be configured in UCP.

The data captured at each level for UCP and the eNZI authentication and authorization backplane is described below:

"none": audit logging is disabled

"metadata":
 - method and API endpoint for the request
 - UCP user which made the request
 - response status (success/failure)
 - timestamp of the call
 - object ID of created/updated resource (for create/update calls)
 - license key
 - remote address

"request": includes all fields from the "metadata" level, as well as the request payload

DTR audits all events associated with repository activities. Events are considered as follows: create, get, delete, update, send, fail, and scan. The following types are associated with the defined audit events: repository, tag, blob, manifest, webhook, uri, promotion, push mirroring, poll mirroring, garbage collector, system.

The Docker Engine - Enterprise component of Docker Enterprise relies on the underlying host operating system's auditing capabilities. By default, the host OS is not configured to audit Docker Engine - Enterprise.

)
  desc 'check', "This check only applies to the underlying host operating system on which the Docker Engine - Enterprise instance is running.

Verify that the auditing capabilities provided by the underlying host have been properly configured to audit Docker Engine - Enterprise:

(Linux) Check that auditd has been installed and that audit rules are configured against the following components of Docker Engine - Enterprise:

auditctl -l | grep -e /usr/bin/docker -e /var/lib/docker -e /etc/docker -e /etc/default/docker -e /etc/docker/daemon.json -e /usr/bin/docker-containerd -e /usr/bin/docker-runc

systemctl show -p FragmentPath docker.service or auditctl -l | grep docker.service
systemctl show -p FragmentPath docker.socket or auditctl -l | grep docker.sock

If audit rules aren't properly configured for the paths and services listed above, then this is a finding."
  desc 'fix', 'This fix applies to the underlying host operating system on which the Docker Engine - Enterprise instance is running.

Enable and configure audit policies for Docker Engine - Enterprise on the host operating system:

(Linux) Check that auditd has been installed, and add the following rules to /etc/audit/audit.rules:

auditctl -w /usr/bin/docker -k
auditctl -w /var/lib/docker -k docker
auditctl -w /etc/docker -k docker
auditctl -w [docker.service-path] -k docker (where [docker.service-path] is the result of systemctl show -p FragmentPath docker.service)
auditctl -w [docker.socket-path] -k docker (where [docker.socket-path] is the result of systemctl show -p FragmentPath docker.socket)
auditctl -w /etc/default/docker -k docker
auditctl -w /etc/docker/daemon.json
auditctl -w /usr/bin/docker-containerd -k docker
auditctl -w /usr/bin/docker-runc -k docker'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-38998r627462_chk'
  tag severity: 'medium'
  tag gid: 'V-235779'
  tag rid: 'SV-235779r627464_rule'
  tag stig_id: 'DKER-EE-001090'
  tag gtitle: 'SRG-APP-000016'
  tag fix_id: 'F-38961r627463_fix'
  tag satisfies: ['SRG-APP-000016', 'SRG-APP-000090', 'SRG-APP-000091', 'SRG-APP-000097', 'SRG-APP-000098', 'SRG-APP-000496', 'SRG-APP-000504', 'SRG-APP-000510', 'SRG-APP-000509', 'SRG-APP-000508', 'SRG-APP-000507', 'SRG-APP-000506', 'SRG-APP-000505', 'SRG-APP-000503', 'SRG-APP-000502', 'SRG-APP-000500', 'SRG-APP-000499', 'SRG-APP-000498', 'SRG-APP-000497', 'SRG-APP-000495', 'SRG-APP-000494', 'SRG-APP-000493', 'SRG-APP-000492', 'SRG-APP-000485', 'SRG-APP-000484', 'SRG-APP-000381', 'SRG-APP-000343', 'SRG-APP-000115', 'SRG-APP-000111', 'SRG-APP-000101', 'SRG-APP-000100', 'SRG-APP-000099', 'SRG-APP-000096', 'SRG-APP-000095', 'SRG-APP-000092', 'SRG-APP-000089', 'SRG-APP-000501', 'SRG-APP-000447']
  tag 'documentable'
  tag legacy: ['SV-104701', 'V-95111']
  tag cci: ['CCI-001814', 'CCI-001464', 'CCI-001487', 'CCI-000172', 'CCI-000171', 'CCI-000169', 'CCI-000154', 'CCI-000158', 'CCI-000134', 'CCI-000135', 'CCI-000132', 'CCI-000133', 'CCI-000067', 'CCI-000130', 'CCI-000131', 'CCI-002723', 'CCI-002724', 'CCI-002234', 'CCI-002754']
  tag nist: ['CM-5 (1)', 'AU-14 (1)', 'AU-3 f', 'AU-12 c', 'AU-12 b', 'AU-12 a', 'AU-6 (4)', 'AU-7 (1)', 'AU-3 e', 'AU-3 (1)', 'AU-3 c', 'AU-3 d', 'AC-17 (1)', 'AU-3 a', 'AU-3 b', 'SI-7 (8)', 'SI-7 (8)', 'AC-6 (9)', 'SI-10 (3)']
end
