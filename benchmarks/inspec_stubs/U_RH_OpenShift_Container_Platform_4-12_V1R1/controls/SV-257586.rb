control 'SV-257586' do
  title 'OpenShift must continuously scan components, containers, and images for vulnerabilities.'
  desc 'Finding vulnerabilities quickly within the container platform and within containers deployed within the platform is important to keep the overall platform secure. When a vulnerability within a component or container is unknown or allowed to remain unpatched, other containers and customers within the platform become vulnerability. The vulnerability can lead to the loss of application data, organizational infrastructure data, and Denial-of-Service (DoS) to hosted applications.

Vulnerability scanning can be performed by the container platform or by external applications.'
  desc 'check', "To check if the Container Security Operator is running, execute the following:

oc get deploy -n openshift-operators container-security-operator -ojsonpath='{.status.readyReplicas}'

If this command returns an error or the number 0, and a separate tool is not being used to perform continuous vulnerability scans of components, containers, and container images, this is a finding."
  desc 'fix', "Vulnerability scanning can be performed by the Container Security Operator, Red Hat Advanced Cluster Security (formerly StackRox) or by external applications. Follow instructions from the application vendor if using external tool for vulnerability scanning. To install the Container Security Operator into the cluster, run the following:

oc apply -f - << 'EOF'
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  labels:
    operators.coreos.com/container-security-operator.openshift-operators: ''
  name: container-security-operator
  namespace: openshift-operators
spec:
  channel: stable-3.8
  installPlanApproval: Automatic
  name: container-security-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF"
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61321r921699_chk'
  tag severity: 'medium'
  tag gid: 'V-257586'
  tag rid: 'SV-257586r921701_rule'
  tag stig_id: 'CNTR-OS-001060'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-61245r921700_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
