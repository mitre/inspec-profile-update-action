control 'SV-242440' do
  title 'Kubernetes API Server must disable token authentication to protect information in transit.'
  desc 'Kubernetes token authentication uses password known as secrets in a plaintext file. This file contains sensitive information such as token, username and user uid. This token is used by service accounts within pods to authenticate with the API Server. This information is very valuable for attackers with malicious intent if the service account is privileged having access to the token. With this token a threat actor can impersonate the service account gaining access to the Rest API service.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master Node. Run the command:

grep -i token-auth-file * 

If "token-auth-file" is set in the Kubernetes API server manifest file, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Remove parameter "--token-auth-file".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45715r712674_chk'
  tag severity: 'medium'
  tag gid: 'V-242440'
  tag rid: 'SV-242440r712676_rule'
  tag stig_id: 'CNTR-K8-002630'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45673r712675_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
