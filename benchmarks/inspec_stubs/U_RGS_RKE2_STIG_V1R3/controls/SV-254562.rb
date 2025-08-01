control 'SV-254562' do
  title 'The Kubernetes API server must have anonymous authentication disabled.'
  desc 'The Kubernetes API Server controls Kubernetes via an API interface. A user who has access to the API essentially has root access to the entire Kubernetes cluster. To control access, users must be authenticated and authorized. By allowing anonymous connections, the controls put in place to secure the API can be bypassed.

Setting anonymous authentication to "false" also disables unauthenticated requests from kubelets.

While there are instances where anonymous connections may be needed (e.g., health checks) and Role-Based Access Controls (RBAC) are in place to limit the anonymous access, this access should be disabled, and only enabled when necessary.'
  desc 'check', 'Ensure anonymous-auth argument is set correctly.

Run this command on the RKE2 Control Plane:
/bin/ps -ef | grep kube-apiserver | grep -v grep

If --anonymous-auth is set to "true" or is not configured, this is a finding.'
  desc 'fix', 'Edit the RKE2 Configuration File /etc/rancher/rke2/config.yaml on the RKE2 Control Plane and set the following "kube-apiserver-arg" argument:

- anonymous-auth=false

Once the configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server'
  impact 0.7
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58046r859254_chk'
  tag severity: 'high'
  tag gid: 'V-254562'
  tag rid: 'SV-254562r918256_rule'
  tag stig_id: 'CNTR-R2-000160'
  tag gtitle: 'SRG-APP-000033-CTR-000100'
  tag fix_id: 'F-57995r918235_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
