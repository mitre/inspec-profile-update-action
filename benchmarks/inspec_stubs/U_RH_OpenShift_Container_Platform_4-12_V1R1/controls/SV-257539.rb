control 'SV-257539' do
  title 'OpenShift runtime must enforce ports, protocols, and services that adhere to the PPSM CAL.'
  desc 'OpenShift Container Platform uses several IPV4 and IPV6 ports and protocols to facilitate cluster communication and coordination. Not all these ports are identified and approved by the PPSM CAL. Those ports, protocols, and services that fall outside the PPSM CAL must be blocked by the runtime or registered. 

Instructions on the PPSM can be found in DOD Instruction 8551.01 Policy.'
  desc 'check', %q(Review the OpenShift documentation and configuration.

For additional information, refer to https://docs.openshift.com/container-platform/4.12/installing/installing_platform_agnostic/installing-platform-agnostic.html.

1. Interview the application administrator.

2. Identify the TCP/IP port numbers OpenShift is configured to use and is utilizing by using a combination of relevant OS commands and application configuration utilities.

3. Identify the network ports and protocols that are used by kube-apiserver by executing the following:

oc get configmap kube-apiserver-pod -n openshift-kube-apiserver -o "jsonpath={ .data['pod\.yaml'] }" | jq '..|.containerPort?' | grep -v "null"

oc get configmap kube-apiserver-pod -n openshift-kube-apiserver -o "jsonpath={ .data['pod\.yaml'] }" | jq '..|.hostPort?' | grep -v "null"

oc get services -A --show-labels | grep apiserver | awk '{print $6,$8}' | grep apiserver

4. Identify the network ports and protocols used by kube-scheduler by executing the following:

oc get configmap kube-scheduler-pod -n openshift-kube-scheduler -o "jsonpath={ .data['pod\.yaml'] }" | jq '..|.containerPort?' | grep -v "null"

oc get services -A --show-labels | grep scheduler | awk '{print $6,$8}' | grep scheduler

5. Identify the network ports and protocols used by kube-controller-manager by executing the following:

oc get configmap kube-controller-manager-pod -n openshift-kube-controller-manager -o "jsonpath={ .data['pod\.yaml'] }" | jq '..|.containerPort?' | grep -v "null"

oc get services -A --show-labels | grep kube-controller

6. Identify the network ports and protocols used by etcd by executing the following:

oc get configmap etcd-pod -n openshift-etcd -o "jsonpath={ .data['pod\.yaml'] }" | grep -Po '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+' | sort -u

Review the PPSM web page at: http://www.disa.mil/Network-Services/Enterprise-Connections/PPSM.

Review the PPSM Category Assurance List (CAL) directly at the following link: https://disa.deps.mil/ext/cop/iase/ppsm/Pages/cal.aspx.

Verify the ports used by the OpenShift are approved by the PPSM CAL.

If the ports, protocols, and services have not been registered locally, this is a finding.)
  desc 'fix', "Verify the accreditation documentation lists all interfaces and the ports, protocols, and services used.

Register OpenShift's ports, protocols, and services with PPSM."
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61274r921558_chk'
  tag severity: 'medium'
  tag gid: 'V-257539'
  tag rid: 'SV-257539r921560_rule'
  tag stig_id: 'CNTR-OS-000390'
  tag gtitle: 'SRG-APP-000142-CTR-000325'
  tag fix_id: 'F-61198r921559_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
