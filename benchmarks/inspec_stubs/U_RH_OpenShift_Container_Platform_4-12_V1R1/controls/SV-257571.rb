control 'SV-257571' do
  title 'OpenShift must contain the latest images with most recent updates and execute within the container platform runtime as authorized by IAVM, CTOs, DTMs, and STIGs.'
  desc 'It is critical to the security and stability of the container platform and the software services running on the platform to ensure that images are deployed through a trusted software supply chain. The OpenShift platform can be configured to limit and control which image source repositories may be used by the platform and the users of the platform. By configuring this to only allow users to deploy images from trusted sources, lowers the risk for a user to deploy unsafe or untested images that would be detrimental to the security and stability of the platform.

In order to help users manage images, OpenShift uses image streams to provide a level of obstruction for the users. In this way the users can trigger automatic redeployments as images are updated. It is also possible to configure the image stream to periodically check the image source repository for any updates and automatically pull in the latest updates.'
  desc 'check', %q(Verify the image source policy is configured by executing the following:

 oc get image.config.openshift.io/cluster -o jsonpath='{.spec.registrySources}{"\nAllowedRegistriesForImport: "}{.spec.allowedRegistriesForImport}{"\n"}'

If nothing is returned, this is a finding. 

If the registries listed under allowedRegistries, insecureRegistries, or AllowedRegistriesForImport are not from trusted sources as defined by the organization, this is a finding.)
  desc 'fix', 'Edit the cluster image config resource to define the allowed registries by executing the following:

oc edit image.config.openshift.io/cluster

The following is an example configuration. For a detailed explanation of the configuration properties, refer to https://docs.openshift.com/container-platform/4.8/openshift_images/image-configuration.html.

----------------------------------------------------------------------
apiVersion: config.openshift.io/v1
kind: Image 
metadata:
  annotations:
    release.openshift.io/create-only: "true"
  creationTimestamp: "2019-05-17T13:44:26Z"
  generation: 1
  name: cluster
  resourceVersion: "8302"
  selfLink: /apis/config.openshift.io/v1/images/cluster
  uid: e34555da-78a9-11e9-b92b-06d6c7da38dc
spec:
  allowedRegistriesForImport: 
    - domainName: quay.io
      insecure: false
  additionalTrustedCA: 
    name: myconfigmap
  registrySources: 
    allowedRegistries:
    - example.com
    - quay.io
    - registry.redhat.io
    - image-registry.openshift-image-registry.svc:5000
    - reg1.io/myrepo/myapp:latest
    insecureRegistries:
    - insecure.com
status:
  internalRegistryHostname: image-registry.openshift-image-registry.svc:5000
----------------------------------------------------------------------'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61306r921654_chk'
  tag severity: 'medium'
  tag gid: 'V-257571'
  tag rid: 'SV-257571r921656_rule'
  tag stig_id: 'CNTR-OS-000890'
  tag gtitle: 'SRG-APP-000456-CTR-001125'
  tag fix_id: 'F-61230r921655_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
