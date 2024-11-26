control 'SV-242438' do
  title 'Kubernetes API Server must configure timeouts to limit attack surface.'
  desc 'Kubernetes API Server request timeouts sets the duration a request stays open before timing out. Since the API Server is the central component in the Kubernetes Control Plane, it is vital to protect this service. If request timeouts were not set, malicious attacks or unwanted activities might affect multiple deployments across different applications or environments. This might deplete all resources from the Kubernetes infrastructure causing the information system to go offline. The request-timeout value must never be set to "0". This disables the request-timeout feature. By default, the request-timeout is set to "1 minute".'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master Node. Run the command:

grep -I request-timeout * 

If Kubernetes API Server manifest file does not exist, this is a finding. 
If the setting request-timeout is set to "0" in the Kubernetes API Server manifest file, or is not configured this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the value of request-timeout greater than "0".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45713r754801_chk'
  tag severity: 'medium'
  tag gid: 'V-242438'
  tag rid: 'SV-242438r754802_rule'
  tag stig_id: 'CNTR-K8-002600'
  tag gtitle: 'SRG-APP-000435-CTR-001070'
  tag fix_id: 'F-45671r712669_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
