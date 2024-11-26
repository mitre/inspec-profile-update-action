control 'SV-254556' do
  title 'The Kubernetes Controller Manager must have secure binding.'
  desc 'Limiting the number of attack vectors and implementing authentication and encryption on the endpoints available to external sources is paramount when securing the overall Kubernetes cluster. The Controller Manager API service exposes port 10252/TCP by default for health and metrics information use. This port does not encrypt or authenticate connections. If this port is exposed externally, an attacker can use this port to attack the entire Kubernetes cluster. By setting the bind address to only localhost (i.e., 127.0.0.1), only those internal services that require health and metrics information can access the Control Manager API.'
  desc 'check', 'Ensure bind-address is set correctly. 

Run this command on the RKE2 Control Plane:
/bin/ps -ef | grep kube-controller-manager | grep -v grep

If --bind-address is not set to "127.0.0.1" or is not configured, this is a finding.'
  desc 'fix', 'Edit the Controller Manager pod specification file /var/lib/rancher/rke2/agent/pod-manifests/kube-controller-manager.yaml on the RKE2 Control Plane to set the below parameter:
--bind-address argument=127.0.0.1

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58040r859236_chk'
  tag severity: 'medium'
  tag gid: 'V-254556'
  tag rid: 'SV-254556r859238_rule'
  tag stig_id: 'CNTR-R2-000100'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag fix_id: 'F-57989r859237_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
