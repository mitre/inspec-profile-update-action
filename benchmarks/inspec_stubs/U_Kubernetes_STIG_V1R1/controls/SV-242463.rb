control 'SV-242463' do
  title 'The Kubernetes API Server must be set to audit log maximum backup.'
  desc 'The Kubernetes API Server must set enough storage to retain logs for monitoring suspicious activity and system misconfiguration, and provide evidence for Cyber Security Investigations.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Master Node. Run the command:

grep -i audit-log-maxbackup * 

If the setting "audit-log-maxbackup" is not set in the Kubernetes API Server manifest file or it is set less than "10", this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the value of "--audit-log-maxbackup" to a minimum of "10".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45738r712743_chk'
  tag severity: 'medium'
  tag gid: 'V-242463'
  tag rid: 'SV-242463r712745_rule'
  tag stig_id: 'CNTR-K8-003300'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45696r712744_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
