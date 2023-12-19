control 'SV-242397' do
  title 'The Kubernetes kubelet static PodPath must not enable static pods.'
  desc 'Allowing kubelet to set a staticPodPath gives containers with root access permissions to traverse the hosting filesystem. The danger comes when the container can create a manifest file within the /etc/kubernetes/manifests directory. When a manifest is created within this directory, containers are entirely governed by the Kubelet not the API Server. The container is not susceptible to admission control at all. Any containers or pods that are instantiated in this manner are called "static pods" and are meant to be used for pods such as the API server, scheduler, controller, etc., not workload pods that need to be governed by the API Server.'
  desc 'check', 'On the Master and Worker nodes, change to the /etc/sysconfig/ directory and run the command:

grep -i staticPodPath kubelet

If any of the nodes return a value for staticPodPath, this is a finding.'
  desc 'fix', 'Edit the kubelet file on each node under the /etc/sysconfig directory to remove the staticPodPath setting and restart the kubelet service by executing the command:

service kubelet restart'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45672r712545_chk'
  tag severity: 'high'
  tag gid: 'V-242397'
  tag rid: 'SV-242397r712547_rule'
  tag stig_id: 'CNTR-K8-000440'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag fix_id: 'F-45630r712546_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
