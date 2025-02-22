control 'SV-257538' do
  title 'OpenShift must contain only container images for those capabilities being offered by the container platform.'
  desc 'Allowing container images to reside within the container platform registry that are not essential to the capabilities being offered by the container platform becomes a potential security risk. By allowing these nonessential container images to exist, the possibility for accidental instantiation exists. The images may be unpatched, not supported, or offer nonapproved capabilities. Those images for customer services are considered essential capabilities.'
  desc 'check', 'To review the container images within the container platform registry, execute the following:

oc get images

Review the container platform container images to validate that only container images necessary for the functionality of the information system are present. If unnecessary container images exist, this is a finding.'
  desc 'fix', 'Remove any images from the container registry that are not required for the functionality of the system by executing the following:

oc delete image <IMAGE_NAME> -n <IMAGE_NAMESPACE>'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61273r921555_chk'
  tag severity: 'medium'
  tag gid: 'V-257538'
  tag rid: 'SV-257538r921557_rule'
  tag stig_id: 'CNTR-OS-000380'
  tag gtitle: 'SRG-APP-000141-CTR-000320'
  tag fix_id: 'F-61197r921556_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
