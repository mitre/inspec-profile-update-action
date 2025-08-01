control 'SV-242386' do
  title 'The Kubernetes API server must have the insecure port flag disabled.'
  desc %q(By default, the API server will listen on two ports. One port is the secure port and the other port is called the "localhost port". This port is also called the "insecure port", port 8080. Any requests to this port bypass authentication and authorization checks. If this port is left open, anyone who gains access to the host on which the master is running can bypass all authorization and authentication mechanisms put in place, and have full control over the entire cluster.

Close the insecure port by setting the API server's --insecure-port flag to "0", ensuring that the --insecure-bind-address is not set.)
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Run the command:

grep -i insecure-port * 

If the setting insecure-port is not set to "0" or is not configured in the Kubernetes API server manifest file, this is a finding.

NOTE: --insecure-port flag has been deprecated and can only be set to 0, **This flag  will be removed in v1.24.*'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node.

Set the argument --insecure-port to "0".'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45661r808572_chk'
  tag severity: 'high'
  tag gid: 'V-242386'
  tag rid: 'SV-242386r808574_rule'
  tag stig_id: 'CNTR-K8-000320'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45619r808573_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
