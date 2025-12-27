control 'SV-254561' do
  title 'The Kubernetes kubelet must enable explicit authorization.'
  desc 'Kubelet is the primary agent on each node. The API server communicates with each kubelet to perform tasks such as starting/stopping pods. By default, kubelets allow all authenticated requests, even anonymous ones, without requiring any authorization checks from the API server. This default behavior bypasses any authorization controls put in place to limit what users may perform within the Kubernetes cluster. To change this behavior, the default setting of AlwaysAllow for the authorization mode must be set to "Webhook".'
  desc 'check', 'Ensure authorization-mode is set correctly in the kubelet on each rke2 node.

Run this command on each node:
/bin/ps -ef | grep kubelet | grep -v grep

If --authorization-mode is not set to "Webhook" or is not configured, this is a finding.'
  desc 'fix', 'Edit the RKE2 Configuration File /etc/rancher/rke2/config.yaml on every RKE2 node and set the following "kubelet-arg" argument:

- authorization-mode=Webhook

Once the configuration file is updated, restart the RKE2 Server or Agent. Run the command:
systemctl restart rke2-server or systemctl restart rke2-agent'
  impact 0.7
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58045r918232_chk'
  tag severity: 'high'
  tag gid: 'V-254561'
  tag rid: 'SV-254561r918255_rule'
  tag stig_id: 'CNTR-R2-000150'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-57994r918233_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
