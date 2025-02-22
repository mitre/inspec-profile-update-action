control 'SV-257574' do
  title 'OpenShift must perform verification of the correct operation of security functions: upon startup and/or restart; upon command by a user with privileged access; and/or every 30 days.'
  desc 'Security functionality includes, but is not limited to, establishing system accounts, configuring access authorization (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

The Compliance Operator enables continuous compliance monitoring within OpenShift. It regularly assesses the environment against defined compliance policies and automatically detects and reports any deviations. This helps organizations maintain a proactive stance towards compliance, identify potential issues in real-time, and take corrective actions promptly.

The Compliance Operator assesses compliance of both the Kubernetes API resources of OpenShift Container Platform, as well as the nodes running the cluster. 

The Compliance Operator uses OpenSCAP, a NIST-certified tool, to scan and enforce security policies provided by the content. This allows an organization to define organizational policy to align with the SSP, combine it with standardized vendor-provided content, and periodically scan the platform in accordance with organization-defined policy.'
  desc 'check', %q(If Red Hat OpenShift Compliance Operator is not used, this check is Not Applicable.

Review the cluster configuration to validate that all required security functions are being validated with the Compliance Operator.

To map the schedule of every profile through its ScanSettingBinding and output the schedules on which each Profile or TailoredProfile is run, execute the following commands:
 
declare -A binding_profiles
 declare -A binding_schedule
 while read binding setting profiles; do binding_profiles[$binding]="$profiles"; binding_schedule[$binding]=$(oc get scansetting -n openshift-compliance $setting -ojsonpath='{.schedule}'); done < <(oc get scansettingbinding -n openshift-compliance -ojsonpath='{range .items[*]}{.metadata.name} {.settingsRef.name} {range .profiles[*]}{.name} {end}{"\n"}{end}')
 for binding in "${!binding_profiles[@]}"; do for profile in ${binding_profiles[$binding]}; do echo "$profile: ${binding_schedule[$binding]}"; done; done

If any error is returned, this is a finding.

If the schedules are not at least monthly or within the organizationally defined periodicity, this is a finding.

Check the profiles that are bound to schedules by executing the following:

To determine which rules are enforced by the profiles that are currently bound to the scheduled periodicities, execute the following commands:

for binding in "${!binding_profiles[@]}"; do for profile in ${binding_profiles[$binding]}; do for rule in $(oc get profile.compliance $profile -n openshift-compliance -ojsonpath='{range .rules[*]}{$}{"\n"}{end}'); do echo "$rule: ${binding_schedule[$binding]}"; done; done; done | sort -u

If the profiles that are bound to schedules do not cover the organization-designed security functions, this is a finding.)
  desc 'fix', %q(If Red Hat OpenShift Compliance Operator is not used, this check is Not Applicable.

The compliance operator must be leveraged to ensure that components are configured in alignment with the SSP at a desired schedule. Install the Compliance Operator by executing the following:

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

Following installation of the Compliance Operator, a ScanSettingBinding object that configures the Compliance Operator to use the desired scan cadence must be created. If users have the definition for ScanSettingBinding in a YAML file named my-scansettingbinding.yml, users would apply that ScanSettingBinding by executing the following:

oc apply -f my-scansettingbinding.yml -n openshift-compliance

For more information about the compliance operator and its use, including the configurability of scheduling of scan cadence in ScanSetting resources and the role-based access control requirements for manually triggered scans, refer to https://docs.openshift.com/container-platform/4.8/security/compliance_operator/compliance-operator-understanding.html.)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61309r921663_chk'
  tag severity: 'medium'
  tag gid: 'V-257574'
  tag rid: 'SV-257574r921665_rule'
  tag stig_id: 'CNTR-OS-000920'
  tag gtitle: 'SRG-APP-000473-CTR-001175'
  tag fix_id: 'F-61233r921664_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
