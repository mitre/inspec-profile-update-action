control 'SV-254558' do
  title 'The Kubernetes API server must have the insecure port flag disabled.'
  desc %q(By default, the API server will listen on two ports. One port is the secure port and the other port is called the "localhost port". This port is also called the "insecure port", port 8080. Any requests to this port bypass authentication and authorization checks. If this port is left open, anyone who gains access to the host on which the master is running can bypass all authorization and authentication mechanisms put in place, and have full control over the entire cluster.

Close the insecure port by setting the API server's --insecure-port flag to "0", ensuring that the --insecure-bind-address is not set.)
  desc 'check', 'Ensure insecure-port is set correctly.

Run this command on the RKE2 Control Plane:
/bin/ps -ef | grep kube-apiserver | grep -v grep

If --insecure-port is not set to "0" or is not configured, this is a finding.'
  desc 'fix', 'Edit the /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml file 
--insecure-port = 0

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server'
  impact 0.7
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58042r870250_chk'
  tag severity: 'high'
  tag gid: 'V-254558'
  tag rid: 'SV-254558r870252_rule'
  tag stig_id: 'CNTR-R2-000120'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-57991r859243_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
