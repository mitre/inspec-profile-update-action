control 'SV-242458' do
  title 'The Kubernetes API Server must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes manifests are those files that contain the arguments and settings for the Control Plane services. These services are etcd, the API Server, controller, proxy, and scheduler. If these files can be changed, the scheduler will be implementing the changes immediately. Many of the security settings within the document are implemented through these manifests.'
  desc 'check', 'Review the permissions of the Kubernetes Kubelet by using the command:

stat -c %a  /etc/kubernetes/manifests/*

If any of the files are have permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of the manifest files by executing the command:

chmod 644 /etc/kubernetes/manifests/*'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45733r712728_chk'
  tag severity: 'medium'
  tag gid: 'V-242458'
  tag rid: 'SV-242458r879887_rule'
  tag stig_id: 'CNTR-K8-003250'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45691r754805_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
