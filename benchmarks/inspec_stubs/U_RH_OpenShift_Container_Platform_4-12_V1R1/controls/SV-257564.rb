control 'SV-257564' do
  title 'OpenShift keystore must implement encryption to prevent unauthorized disclosure of information at rest within the container platform.'
  desc 'By default, etcd data is not encrypted in OpenShift Container Platform. Enable etcd encryption for the cluster to provide an additional layer of data security. For example, it can help protect the loss of sensitive data if an etcd backup is exposed to the incorrect parties. When users enable etcd encryption, the following OpenShift API server and Kubernetes API server resources are encrypted:

Secrets

Config maps

Routes

OAuth access tokens

OAuth authorize tokens

When users enable etcd encryption, encryption keys are created. These keys are rotated on a weekly basis. Users must have these keys to restore from an etcd backup.'
  desc 'check', 'Review the API server encryption by running by executing the following:

oc edit apiserver

EXAMPLE OUTPUT
spec:
  encryption:
    type: aescbc 

If the encryption type is not "aescbc", this is a finding.'
  desc 'fix', 'Set API encryption type by executing the following:

oc edit apiserver

Set the encryption field type to aescbc:
spec:
  encryption:
    type: aescbc 

Additional details about the configuration can be found in the documentation:
https://docs.openshift.com/container-platform/4.8/security/encrypting-etcd.html'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61299r921633_chk'
  tag severity: 'medium'
  tag gid: 'V-257564'
  tag rid: 'SV-257564r921635_rule'
  tag stig_id: 'CNTR-OS-000780'
  tag gtitle: 'SRG-APP-000429-CTR-001060'
  tag fix_id: 'F-61223r921634_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
