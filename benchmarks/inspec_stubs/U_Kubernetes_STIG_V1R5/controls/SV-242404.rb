control 'SV-242404' do
  title 'Kubernetes Kubelet must deny hostname override.'
  desc 'Kubernetes allows for the overriding of hostnames. Allowing this feature to be implemented within the kubelets may break the TLS setup between the kubelet service and the API server. This setting also can make it difficult to associate logs with nodes if security analytics needs to take place. The better practice is to setup nodes with resolvable FQDNs and avoid overriding the hostnames.'
  desc 'check', 'On the Master and each Worker node, change to the /etc/sysconfig/ directory and run the command:

grep -i hostname-override kubelet  
--hostname-override

If any of the nodes have the setting "hostname-override" present, this is a finding.'
  desc 'fix', 'Edit the Kubernetes Kubelet file in the /etc/sysconfig directory on the Master and Worker nodes and remove the "--hostname-override" setting. Restart the service after the change is made by running:

service kubelet restart'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45679r712566_chk'
  tag severity: 'medium'
  tag gid: 'V-242404'
  tag rid: 'SV-242404r712568_rule'
  tag stig_id: 'CNTR-K8-000850'
  tag gtitle: 'SRG-APP-000133-CTR-000290'
  tag fix_id: 'F-45637r712567_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
