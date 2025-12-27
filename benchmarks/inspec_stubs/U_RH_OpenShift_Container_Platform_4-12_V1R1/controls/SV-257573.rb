control 'SV-257573' do
  title 'The Compliance Operator must be configured.'
  desc 'The Compliance Operator enables continuous compliance monitoring within OpenShift. It regularly assesses the environment against defined compliance policies and automatically detects and reports any deviations. This helps organizations maintain a proactive stance towards compliance, identify potential issues in real-time, and take corrective actions promptly.

The Compliance Operator assesses compliance of both the Kubernetes API resources of OpenShift Container Platform, as well as the nodes running the cluster. 

The Compliance Operator uses OpenSCAP, a NIST-certified tool, to scan and enforce security policies provided by the content. This allows an organization to define organizational policy to align with the SSP, combine it with standardized vendor-provided content, and periodically scan the platform in accordance with organization-defined policy.'
  desc 'check', 'If Red Hat OpenShift Compliance Operator is not used, this check is Not Applicable.
Note: If Red Hat OpenShift Compliance Operator is not used, run the checks manually.

Review the cluster configuration to validate that all required security functions are being validated with the Compliance Operator.

To determine if any scans have been applied to the cluster and the status of the scans, execute the following:

oc get compliancescan -n openshift-compliance

Example output:
NAME PHASE RESULT
ocp4-cis DONE NON-COMPLIANT
ocp4-cis-manual DONE NON-COMPLIANT
ocp4-cis-node-master DONE NON-COMPLIANT
ocp4-cis-node-master-manual DONE NON-COMPLIANT
ocp4-cis-node-worker DONE NON-COMPLIANT
ocp4-cis-node-worker-manual DONE NON-COMPLIANT
ocp4-moderate DONE NON-COMPLIANT
ocp4-moderate-manual DONE NON-COMPLIANT
rhcos4-moderate-master DONE NON-COMPLIANT
rhcos4-moderate-master-manual DONE NON-COMPLIANT
rhcos4-moderate-worker DONE NON-COMPLIANT
rhcos4-moderate-worker-manual DONE NON-COMPLIANT

If no ComplianceScan names return, the scans do not align to the organizationally-defined appropriate security functions, the command returns with an error, or any of the results show "NON-COMPLIANT" as their result, then this is a finding.'
  desc 'fix', %q(If Red Hat OpenShift Compliance Operator is not used,, this check is Not Applicable.

The compliance operator must be leveraged to ensure that components are configured in alignment with the SSP. Install the Compliance Operator by executing the following:

oc apply -f - << 'EOF'
---
apiVersion: project.openshift.io/v1
kind: Project
metadata:
  labels:
    kubernetes.io/metadata.name: openshift-compliance
    openshift.io/cluster-monitoring: "true"
  name: openshift-compliance
spec: {}
...
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: compliance-operator
  namespace: openshift-compliance
spec:
  targetNamespaces:
  - openshift-compliance
...
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: compliance-operator
  namespace: openshift-compliance
spec:
  channel: release-0.1
  installPlanApproval: Automatic
  name: compliance-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
...
EOF

Following installation of the Compliance Operator, a ScanSettingBinding object that configures the Compliance Operator to use the desired profile sets must be created. TailoredProfiles enable customization of controls to meet specific organizational controls defined in the SSP and can be based on existing profiles or written from scratch in standard SCAP format. If users have the definition for ScanSettingBinding that aligns profiles with ScanSettings in a YAML file named my-scansettingbinding.yml, users would apply that ScanSettingBinding by executing the following:

oc apply -f my-scansettingbinding.yml -n openshift-compliance

For more information about the compliance operator and its use, including the creation of TailoredProfiles and the ScanSettings available to meet specific security functions or organizational goals defined in the SSP, refer to https://docs.openshift.com/container-platform/4.8/security/compliance_operator/compliance-operator-understanding.html.)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61308r921660_chk'
  tag severity: 'medium'
  tag gid: 'V-257573'
  tag rid: 'SV-257573r921662_rule'
  tag stig_id: 'CNTR-OS-000910'
  tag gtitle: 'SRG-APP-000472-CTR-001170'
  tag fix_id: 'F-61232r921661_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
