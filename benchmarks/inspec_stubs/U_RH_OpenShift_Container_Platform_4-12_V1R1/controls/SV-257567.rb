control 'SV-257567' do
  title 'OpenShift must protect the confidentiality and integrity of transmitted information.'
  desc 'OpenShift provides for two types of application level ingress types, Routes, and Ingresses. Routes have been a part of OpenShift since version 3. Ingresses were promoted out of beta in Aug 2020 (kubernetes v1.19). Routes provides for three type of TLS configuration options; Edge, Passthrough, and Re-encrypt. Each of those options provide TLS encryption over HTTP for inbound transmissions originating outside the cluster. Ingresses will have an IngressController associated that manages the routing and proxying of inbound transmissions.'
  desc 'check', 'Verify that routes and ingress are using secured transmission ports and protocols by executing the following:

oc get routes --all-namespaces

Review the ingress ports, if the Ingress is not using a secure TLS transport, this is a finding.'
  desc 'fix', 'Delete any Route or Ingress that does not use a secure transport.

oc delete route <NAME> -n <NAMESPACE>

or

oc delete ingress <NAME> -n <NAMESPACE>'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61302r921642_chk'
  tag severity: 'medium'
  tag gid: 'V-257567'
  tag rid: 'SV-257567r921644_rule'
  tag stig_id: 'CNTR-OS-000820'
  tag gtitle: 'SRG-APP-000439-CTR-001080'
  tag fix_id: 'F-61226r921643_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
