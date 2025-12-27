control 'SV-257570' do
  title 'OpenShift must remove old components after updated versions have been installed.'
  desc 'Previous versions of OpenShift components that are not removed from the container platform after updates have been installed may be exploited by adversaries by causing older components to execute which contain vulnerabilities. When these components are deleted, the likelihood of this happening is removed.

'
  desc 'check', %q(Ensure the imagepruner is configured and is not in a suspended state by executing the following:

oc get imagepruners.imageregistry.operator.openshift.io/cluster -o jsonpath='{.spec}{"\n"}'

Review the settings. If "suspend" is set to "true", this is a finding.)
  desc 'fix', %q(Enable the image pruner to automate the pruning of images from the cluster by executing the following:

oc patch imagepruners.imageregistry.operator.openshift.io/cluster --type=merge -p '{"spec":{"suspend":false}}'

For additional details on configuring the image pruner operator, refer to the following document:
https://docs.openshift.com/container-platform/4.8/applications/pruning-objects.html#pruning-images_pruning-objects)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61305r921651_chk'
  tag severity: 'medium'
  tag gid: 'V-257570'
  tag rid: 'SV-257570r921653_rule'
  tag stig_id: 'CNTR-OS-000880'
  tag gtitle: 'SRG-APP-000454-CTR-001110'
  tag fix_id: 'F-61229r921652_fix'
  tag satisfies: ['SRG-APP-000454-CTR-001110', 'SRG-APP-000454-CTR-001115']
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
