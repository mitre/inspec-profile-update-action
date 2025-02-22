control 'SV-257561' do
  title 'OpenShift must prevent the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Integrity of the OpenShift platform is handled by the cluster version operator. The cluster version operator will by default GPG verify the integrity of the release image before applying it. The release image contains a sha256 digest of machine-os-content which is used by the machine config operators for updates. On the host, the container runtime (podman) verifies the integrity of that sha256 when pulling the image before the machine config operator reads its content. Hence, there is end-to-end GPG-verified integrity for the operating system updates (as well as the rest of the cluster components which run as regular containers).'
  desc 'check', 'To verify integrity of the cluster version, execute the following:

oc get clusterversion version 

If the Cluster Version Operator is not installed or the AVAILABLE is not set to True, this is a finding. 

Run the following command to retrieve the Cluster Version objects in the system: 

oc get clusterversion version -o yaml

If "verified: true", under status history for each item is not present, this is a finding.'
  desc 'fix', 'By default, the integrity of RH CoreOS is checked by cluster version operator on OpenShift platform. If the integrity is not verified, reinstall of the cluster is necessary.

Refer to instructions:
https://docs.openshift.com/container-platform/4.10/installing/index.html'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61296r921624_chk'
  tag severity: 'medium'
  tag gid: 'V-257561'
  tag rid: 'SV-257561r921626_rule'
  tag stig_id: 'CNTR-OS-000740'
  tag gtitle: 'SRG-APP-000384-CTR-000915'
  tag fix_id: 'F-61220r921625_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
