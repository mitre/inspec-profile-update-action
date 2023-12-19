control 'SV-242461' do
  title 'Kubernetes API Server audit logs must be enabled.'
  desc 'Kubernetes API Server validates and configures pods and services for the API object. The REST operation provides frontend functionality to the cluster share state. Enabling audit logs provides a way to monitor and identify security risk events or misuse of information. Audit logs are necessary to provide evidence in the case the Kubernetes API Server is compromised requiring a Cyber Security Investigation.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Run the command:

grep -i audit-policy-file * 

If the setting "audit-policy-file" is not set or is found in the Kubernetes API manifest file without valid content, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the argument "--audit-policy-file" to "log file directory".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45736r712737_chk'
  tag severity: 'medium'
  tag gid: 'V-242461'
  tag rid: 'SV-242461r712739_rule'
  tag stig_id: 'CNTR-K8-003280'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45694r712738_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
