control 'SV-242405' do
  title 'The Kubernetes manifests must be owned by root.'
  desc 'The manifest files contain the runtime configuration of the API server, proxy, scheduler, controller, and etcd. If an attacker can gain access to these files, changes can be made to open vulnerabilities and bypass user authorizations inherit within Kubernetes with RBAC implemented.'
  desc 'check', 'On the Control Plane, change to the /etc/kubernetes/manifest directory. Run the command:
ls -l *

Each manifest file must be owned by root:root.

If any manifest file is not owned by root:root, this is a finding.'
  desc 'fix', 'On the Control Plane, change to the /etc/kubernetes/manifest directory. Run the command:
chown root:root *

To verify the change took place, run the command:
ls -l *

All the manifest files should be owned by root:root.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45680r863812_chk'
  tag severity: 'medium'
  tag gid: 'V-242405'
  tag rid: 'SV-242405r863981_rule'
  tag stig_id: 'CNTR-K8-000860'
  tag gtitle: 'SRG-APP-000133-CTR-000295'
  tag fix_id: 'F-45638r863813_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
