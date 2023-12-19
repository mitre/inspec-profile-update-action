control 'SV-242392' do
  title 'The Kubernetes kubelet must enable explicit authorization.'
  desc 'Kubelet is the primary agent on each node. The API server communicates with each kubelet to perform tasks such as starting/stopping pods. By default, kubelets allow all authenticated requests, even anonymous ones, without requiring any authorization checks from the API server. This default behavior bypasses any authorization controls put in place to limit what users may perform within the Kubernetes cluster. To change this behavior, the default setting of AlwaysAllow for the authorization mode must be set to "Webhook".'
  desc 'check', 'Change to the /etc/sysconfig/ directory on the Kubernetes Master Node. Run the command:

grep -i authorization-mode kubelet  

On each Worker node, change to the /etc/sysconfig/ directory. Run the command:

grep -i authorization-mode kubelet

If authorization-mode is missing or is set to "AllowAlways" on the Master node or any of the Worker nodes, this is a finding.'
  desc 'fix', 'Edit the Kubernetes Kubelet file in the/etc/sysconfig/ directory on the Kubernetes Master and Worker nodes. 

Set the argument --authorization-mode to "Webhook". 

Restart each kubelet service after the change is made using the command:
service kubelet restart'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45667r712530_chk'
  tag severity: 'high'
  tag gid: 'V-242392'
  tag rid: 'SV-242392r712532_rule'
  tag stig_id: 'CNTR-K8-000380'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45625r717029_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
