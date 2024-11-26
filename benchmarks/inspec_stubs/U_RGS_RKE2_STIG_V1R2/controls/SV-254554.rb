control 'SV-254554' do
  title 'RKE2 must use a centralized user management solution to support account management functions.'
  desc 'The Kubernetes Controller Manager is a background process that embeds core control loops regulating cluster system state through the API Server. Every process executed in a pod has an associated service account. By default, service accounts use the same credentials for authentication. Implementing the default settings poses a high risk to the Kubernetes Controller Manager. Setting the use-service-account-credential value lowers the attack surface by generating unique service accounts settings for each controller instance.'
  desc 'check', 'Ensure use-service-account-credentials argument is set correctly.

Run this command on the RKE2 Control Plane:
/bin/ps -ef | grep kube-controller-manager | grep -v grep

If --use-service-account-credentials argument is not set to "true" or is not configured, this is a finding.'
  desc 'fix', 'Edit the Controller Manager pod specification file /var/lib/rancher/rke2/agent/pod-manifests/kube-controller-manager.yaml on the RKE2 Control Plane to set the below parameter:
--use-service-account-credentials argument=true

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58038r859230_chk'
  tag severity: 'medium'
  tag gid: 'V-254554'
  tag rid: 'SV-254554r879522_rule'
  tag stig_id: 'CNTR-R2-000030'
  tag gtitle: 'SRG-APP-000023-CTR-000055'
  tag fix_id: 'F-57987r859231_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
