control 'SV-254560' do
  title 'The Kubernetes API server must have the insecure bind address not set.'
  desc %q(By default, the API server will listen on two ports and addresses. One address is the secure address and the other address is called the "insecure bind" address and is set by default to localhost. Any requests to this address bypass authentication and authorization checks. If this insecure bind address is set to localhost, anyone who gains access to the host on which the master is running can bypass all authorization and authentication mechanisms put in place and have full control over the entire cluster.

Close or set the insecure bind address by setting the API server's --insecure-bind-address flag to an IP or leave it unset and ensure that the --insecure-bind-port is not set.)
  desc 'check', 'If running rke2 Kubernetes version > 1.20, this requirement is not applicable (NA).

Ensure insecure-bind-address is set correctly. 

Run the command:
ps -ef | grep kube-apiserver

If the setting insecure-bind-address is found and set to "localhost", this is a finding.'
  desc 'fix', 'If running rke2 Kubernetes version > 1.20, this requirement is NA.

Upgrade to a supported version of RKE2 Kubernetes.'
  impact 0.7
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58044r918229_chk'
  tag severity: 'high'
  tag gid: 'V-254560'
  tag rid: 'SV-254560r918254_rule'
  tag stig_id: 'CNTR-R2-000140'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-57993r918230_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
