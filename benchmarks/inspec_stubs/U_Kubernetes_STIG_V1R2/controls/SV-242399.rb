control 'SV-242399' do
  title 'Kubernetes DynamicKubeletConfig must not be enabled.'
  desc 'Kubernetes allows a user to configure kubelets with dynamic configurations. When dynamic configuration is used, the kubelet will watch for changes to the configuration file. When changes are made, the kubelet will automatically restart. Allowing this capability bypasses access restrictions and authorizations. Using this capability, an attacker can lower the security posture of the kubelet, which includes allowing the ability to run arbitrary commands in any container running on that node.'
  desc 'check', %q(On the Master node, change to the manifests' directory at /etc/kubernetes/manifests and run the command:

grep -i feature-gates *

Review the feature-gates setting if one is returned.

If the feature-gates setting does not exist or feature-gates does not contain the DynamicKubeletConfig flag or the "DynamicKubletConfig" flag is set to "true", this is a finding.

Change to the directory /etc/sysconfig on the Master and each Worker node and execute the command:

grep -i feature-gates kubelet

Review every feature-gates setting if one is returned.

If the feature-gates setting does not exist or feature-gates does not contain the DynamicKubeletConfig flag or the DynamicKubletConfig flag is set to "true", this is a finding.)
  desc 'fix', 'Edit any manifest file or kubelet config file that does not contain a feature-gates setting or has DynamicKubeletConfig set to "true".

An omission of DynamicKubeletConfig within the feature-gates defaults to true. Set DynamicKubeletConfig to "false". Restart the kubelet service if the kubelet config file is changed.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45674r712551_chk'
  tag severity: 'medium'
  tag gid: 'V-242399'
  tag rid: 'SV-242399r717021_rule'
  tag stig_id: 'CNTR-K8-000460'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45632r717020_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
