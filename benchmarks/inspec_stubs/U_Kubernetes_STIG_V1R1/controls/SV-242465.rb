control 'SV-242465' do
  title 'The Kubernetes API Server audit log path must be set.'
  desc 'Kubernetes API Server validates and configures pods and services for the API object. The REST operation provides frontend functionality to the cluster share state. Audit logs are necessary to provide evidence in the case the Kubernetes API Server is compromised requiring Cyber Security Investigation. To record events in the audit log the log path value must be set.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master Node. Run the command:

grep -i audit-log-path * 

If the setting audit-log-path is not set in the Kubernetes API Server manifest file or it is set to a valid path, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the value of "--audit-log-path" to valid location.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45740r712749_chk'
  tag severity: 'medium'
  tag gid: 'V-242465'
  tag rid: 'SV-242465r712751_rule'
  tag stig_id: 'CNTR-K8-003320'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45698r712750_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
