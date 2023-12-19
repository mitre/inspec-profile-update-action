control 'SV-242462' do
  title 'The Kubernetes API Server must be set to audit log max size.'
  desc 'The Kubernetes API Server must be set for enough storage to retain log information over the period required. When audit logs are large in size, the monitoring service for events becomes degraded. The function of the maximum log file size is to set these limits.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i audit-log-maxsize * 

If the setting "audit-log-maxsize" is not set in the Kubernetes API Server manifest file or it is set to less than "100", this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of –"--audit-log-maxsize" to a minimum of "100".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45737r863925_chk'
  tag severity: 'medium'
  tag gid: 'V-242462'
  tag rid: 'SV-242462r879887_rule'
  tag stig_id: 'CNTR-K8-003290'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45695r863926_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
