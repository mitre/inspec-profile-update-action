control 'SV-257506' do
  title 'OpenShift must use TLS 1.2 or greater for secure communication.'
  desc 'The authenticity and integrity of the container platform and communication between nodes and components must be secure. If an insecure protocol is used during transmission of data, the data can be intercepted and manipulated. The manipulation of data can be used to inject status changes of the container platform, causing the execution of containers or reporting an incorrect healthcheck. To thwart the manipulation of the data during transmission, a secure protocol (TLS 1.2 or newer) must be used. Further guidance on secure transport protocols can be found in NIST SP 800-52.

'
  desc 'check', 'Verify the TLS Security Profile is not set to a profile that does not enforce TLS 1.2 or above. 

View the TLS security profile for the ingress controllers by executing the following:

oc get --all-namespaces ingresscontrollers.operator.openshift.io -ocustom-columns="NAME":.metadata.name,"NAMESPACE":.metadata.namespace,"TLS PROFILE":.spec.tlsSecurityProfile

View the TLS security profile for the control plane by executing the following:

oc get APIServer cluster -ocustom-columns="TLS PROFILE":.spec.tlsSecurityProfile

View the TLS profile for the Kubelet by executing the following:

oc get kubeletconfigs -ocustom-columns="NAME":.metadata.name,"TLS PROFILE":.spec.tlsSecurityProfile

If any of the above returns a TLS profile of "Old", this is a finding.

If any of the above returns a TLS profile of "Custom" and the minTLSVersion is not set to "VersionTLS12" or greater, this is a finding.

If the above returns "<none>" TLS profile, this is not a finding as the TLS profile defaults to "Intermediate".

If the kubelet TLS profile check does not return any kubeletconfigs, this is not a finding as the default OCP installation uses defaults only.'
  desc 'fix', 'Edit each resource and set the TLS Security Profile to Intermediate by executing the following:

oc edit ingresscontroller <NAME> -n <NAMESPACE>

Add the following to the file:

apiVersion: config.openshift.io/v1
kind: IngressController
 ...
spec:
  tlsSecurityProfile:
    intermediate: {}
    type: Intermediate

Edit API Server by executing the following:

oc edit APIServer

Add the following to the file:

apiVersion: config.openshift.io/v1
kind: APIServer
 ...
spec:
  tlsSecurityProfile:
    intermediate: {}
    type: Intermediate

Edit Kubelet by executing the following:

oc edit KubeletConfig <NAME>

Set to the following:

apiVersion: config.openshift.io/v1
kind: KubeletConfig
 ...
spec:
  tlsSecurityProfile:
    intermediate: {}
    type: Intermediate'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61241r921459_chk'
  tag severity: 'medium'
  tag gid: 'V-257506'
  tag rid: 'SV-257506r921461_rule'
  tag stig_id: 'CNTR-OS-000020'
  tag gtitle: 'SRG-APP-000014-CTR-000040'
  tag fix_id: 'F-61165r921460_fix'
  tag satisfies: ['SRG-APP-000014-CTR-000040', 'SRG-APP-000560-CTR-001340']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-001453']
  tag nist: ['AC-17 (2)', 'AC-17 (2)']
end
