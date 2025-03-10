control 'SV-242387' do
  title 'The Kubernetes Kubelet must have the read-only port flag disabled.'
  desc %q(Kubelet serves a small REST API with read access to port 10255. The read-only port for Kubernetes provides no authentication or authorization security control. Providing unrestricted access on port 10255 exposes Kubernetes pods and containers to malicious attacks or compromise. Port 10255 is deprecated and should be disabled. 

Close the read-only-port by setting the API server's read-only port flag to "0".)
  desc 'check', 'Run the following command on each Worker Node:
ps -ef | grep kubelet 

Verify that the --read-only-port argument exists and is set to "0". 

If the --read-only-port argument exists and is not set to "0", this is a finding. 

If the --read-only-port argument does not exist, check the Master Node Kubelet config file.

On the Kubernetes Master Node, run the command:
ps -ef | grep kubelet
(path identified by: --config)

Verify there is a readOnlyPort entry in the config file and it is set to "0". 

If the --read-only-port argument exists and is not set to "0" this is a finding. 

If "--read-only-port=0" argument does not exist on the worker node and the master node, this is a finding.'
  desc 'fix', 'Edit the Kubernetes Kubelet file in the --config directory on the Kubernetes Master Node. Set the argument --read-only-port to 0.  

Reset Kubelet service using the following command:
service kubelet restart

If using worker node arguments, edit the kubelet service file /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf on each Worker Node: set the parameter in KUBELET_SYSTEM_PODS_ARGS variable to
"--read-only-port=0".'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45662r712515_chk'
  tag severity: 'high'
  tag gid: 'V-242387'
  tag rid: 'SV-242387r717013_rule'
  tag stig_id: 'CNTR-K8-000330'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45620r717012_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
