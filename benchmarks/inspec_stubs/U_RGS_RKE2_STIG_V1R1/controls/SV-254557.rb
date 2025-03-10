control 'SV-254557' do
  title 'The Kubernetes Kubelet must have anonymous authentication disabled.'
  desc 'RKE2 registry is used to store images and is the keeper of truth for trusted images within the platform. To guarantee the images integrity, access to the registry must be limited to those individuals who need to perform tasks to the images such as the update, creation, or deletion of images. Without this control access, images can be deleted that are in use by RKE2 causing a denial of service (DoS), and images can be modified or introduced without going through the testing and validation process allowing for the intentional or unintentional introduction of containers with flaws and vulnerabilities.

By allowing anonymous connections, the controls put in place to secure the Kubelet can be bypassed. Setting anonymous authentication to "false" also disables unauthenticated requests from kubelets.

While there are instances where anonymous connections may be needed (e.g., health checks) and Role-Based Access Controls (RBAC) are in place to limit the anonymous access, this access must be disabled and only enabled when necessary.'
  desc 'check', 'Ensure anonymous-auth is set correctly so anonymous requests will be rejected.

Run this command on each node:
/bin/ps -ef | grep kubelet | grep -v grep

If --anonymous-auth is set to "true" or is not configured, this is a finding.'
  desc 'fix', 'Edit the Kubernetes Kubelet file etc/rancher/rke2/config.yaml on the RKE2 Control Plane and set the following:
--anonymous-auth=false

Once configuration file is updated, restart the RKE2 Agent. Run the command:
systemctl restart rke2-agent'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58041r859239_chk'
  tag severity: 'medium'
  tag gid: 'V-254557'
  tag rid: 'SV-254557r859241_rule'
  tag stig_id: 'CNTR-R2-000110'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag fix_id: 'F-57990r859240_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
