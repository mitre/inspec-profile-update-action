control 'SV-254559' do
  title 'The Kubernetes Kubelet must have the read-only port flag disabled.'
  desc %q(Kubelet serves a small REST API with read access to port 10255. The read-only port for Kubernetes provides no authentication or authorization security control. Providing unrestricted access on port 10255 exposes Kubernetes pods and containers to malicious attacks or compromise. Port 10255 is deprecated and should be disabled. 

Close the read-only-port by setting the API server's read-only port flag to "0".)
  desc 'check', 'Ensure read-only-port is set correctly so anonymous requests will be rejected.

Run this command on each node:
/bin/ps -ef | grep kubelet | grep -v grep

If --read-only-port is not set to "0" or is not configured, this is a finding.'
  desc 'fix', 'Edit the Kubernetes Kubelet file etc/rancher/rke2/config.yaml on the RKE2 Control Plane and set the following:
--read-only-port=0

Once configuration file is updated, restart the RKE2 Agent. Run the command:
systemctl restart rke2-agent'
  impact 0.7
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58043r870253_chk'
  tag severity: 'high'
  tag gid: 'V-254559'
  tag rid: 'SV-254559r879530_rule'
  tag stig_id: 'CNTR-R2-000130'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-57992r859246_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
