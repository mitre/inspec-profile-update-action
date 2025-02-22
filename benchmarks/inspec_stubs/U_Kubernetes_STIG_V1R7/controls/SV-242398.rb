control 'SV-242398' do
  title 'Kubernetes DynamicAuditing must not be enabled.'
  desc 'Protecting the audit data from change or deletion is important when an attack occurs. One way an attacker can cover their tracks is to change or delete audit records. This will either make the attack unnoticeable or make it more difficult to investigate how the attack took place and what changes were made. The audit data can be protected through audit log file protections and user authorization.

One way for an attacker to thwart these measures is to send the audit logs to another source and filter the audited results before sending them on to the original target. This can be done in Kubernetes through the configuration of dynamic audit webhooks through the DynamicAuditing flag.'
  desc 'check', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Review the feature-gates setting, if one is returned.

If the feature-gates setting is available and contains the DynamicAuditing flag set to "true", this is a finding.

Change to the directory /etc/sysconfig on the Control Plane and each Worker Node and execute the command:
grep -i feature-gates kubelet

Review every feature-gates setting that is returned.

If any feature-gates setting is available and contains the "DynamicAuditing" flag set to "true", this is a finding.)
  desc 'fix', 'Edit any manifest files or kubelet config files that contain the feature-gates setting with DynamicAuditing set to "true". Set the flag to "false" or remove the "DynamicAuditing" setting completely. Restart the kubelet service if the kubelet config file if the kubelet config file is changed.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45673r863794_chk'
  tag severity: 'medium'
  tag gid: 'V-242398'
  tag rid: 'SV-242398r863974_rule'
  tag stig_id: 'CNTR-K8-000450'
  tag gtitle: 'SRG-APP-000033-CTR-000100'
  tag fix_id: 'F-45631r717018_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
