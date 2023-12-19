control 'SV-242426' do
  title 'Kubernetes etcd must enable client authentication to secure service.'
  desc 'Kubernetes container and pod configuration are maintained by Kubelet. Kubelet agents register nodes with the API Server, mount volume storage, and perform health checks for containers and pods. Anyone who gains access to Kubelet agents can effectively control applications within the pods and containers. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols, such as TLS. TLS provides the Kubernetes API Server with a means to be able to authenticate sessions and encrypt traffic.

To enable encrypted communication for Kubelet, the parameter etcd-cafile must be set. This parameter gives the location of the SSL Certificate Authority file used to secure Kubelet communication.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Run the command:

grep -i peer-client-cert-auth * 

If the setting peer-client-cert-auth is not configured in the Kubernetes etcd manifest file or set to "false", this is a finding.'
  desc 'fix', 'Edit the Kubernetes etcd file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.

Set the value of "--peer-client-cert-auth" to "true" for the etcd.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45701r754811_chk'
  tag severity: 'medium'
  tag gid: 'V-242426'
  tag rid: 'SV-242426r754813_rule'
  tag stig_id: 'CNTR-K8-001480'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45659r754812_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
