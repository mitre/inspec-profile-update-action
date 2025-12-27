control 'SV-257505' do
  title 'OpenShift must use TLS 1.2 or greater for secure container image transport from trusted sources.'
  desc 'The authenticity and integrity of the container image during the container image lifecycle is part of the overall security posture of the container platform. This begins with the container image creation and pull of a base image from a trusted source for child container image creation and the instantiation of the new image into a running service.

If an insecure protocol is used during transmission of container images at any step of the lifecycle, a bad actor may inject nefarious code into the container image. The container image, when instantiated, then becomes a security risk to the container platform, the host server, and other containers within the container platform. To thwart the injection of code during transmission, a secure protocol (TLS 1.2 or newer) must be used. Further guidance on secure transport protocols can be found in NIST SP 800-52.'
  desc 'check', "Verify that no insecure registries are configured by executing the following:

oc get image.config.openshift.io/cluster -ojsonpath='{.spec.allowedRegistriesForImport}' | jq -r '.[] | select(.insecure == true)'

If the above query finds any registries, this is a finding. Empty output is not a finding.

Verify that no insecure registries are configured by executing the following:

oc get image.config.openshift.io/cluster -ojsonpath='{.spec.registrySources.insecureRegistries}'  

If the above query returns anything, then this is a finding. Empty output is not a finding."
  desc 'fix', "Remove insecure registries from the cluster's image registry configuration by executing the following:

oc edit image.config.openshift.io/cluster

Edit or remove any registries where insecure is set to true or are listed under insecureRegistries.

Refer to https://docs.openshift.com/container-platform/4.8/openshift_images/image-configuration.html for more details on configuring registries in OpenShift."
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61240r921456_chk'
  tag severity: 'medium'
  tag gid: 'V-257505'
  tag rid: 'SV-257505r921458_rule'
  tag stig_id: 'CNTR-OS-000010'
  tag gtitle: 'SRG-APP-000014-CTR-000035'
  tag fix_id: 'F-61164r921457_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
