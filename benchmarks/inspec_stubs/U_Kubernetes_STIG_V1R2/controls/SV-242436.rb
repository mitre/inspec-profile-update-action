control 'SV-242436' do
  title 'The Kubernetes API server must have the ValidatingAdmissionWebhook enabled.'
  desc 'Enabling the admissions webhook allows for Kubernetes to apply policies against objects that are to be created, read, updated, or deleted. By applying a pod security policy, control can be given to not allow images to be instantiated that run as the root user. If pods run as the root user, the pod then has root privileges to the host system and all the resources it has. An attacker can use this to attack the Kubernetes cluster. By implementing a policy that does not allow root or privileged pods, the pod users are limited in what the pod can do and access.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Run the command:

grep -i ValidatingAdmissionWebhook * 

If a line is not returned that includes enable-admission-plugins and ValidatingAdmissionWebhook, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Master Node. Set the argument "--enable-admission-plugins" to include "ValidatingAdmissionWebhook".  Each enabled plugin is separated by commas.

Note: It is best to implement policies first and then enable the webhook, otherwise a denial of service may occur.'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45711r712662_chk'
  tag severity: 'high'
  tag gid: 'V-242436'
  tag rid: 'SV-242436r712664_rule'
  tag stig_id: 'CNTR-K8-002000'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag fix_id: 'F-45669r717027_fix'
  tag 'documentable'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
