control 'SV-254571' do
  title 'Rancher RKE2 must prevent nonprivileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Admission controllers intercept requests to the Kubernetes API before an object is instantiated. Enabling the admissions webhook allows for Kubernetes to apply policies against objects that are to be created, read, updated or deleted.

Admissions controllers can be used for:
- Prevent pod’s ability to run privileged containers
- Prevent pod’s ability to use privileged escalation
- Controlling pod’s access to volume types
- Controlling pod’s access to host file system
- Controlling pod’s usage of host networking objects and configuration

'
  desc 'check', 'If using RKE2 v1.24 or older:

On the Server Node, run the command:

kubectl get podsecuritypolicy

For any pod security policies listed, with the exception of system-unrestricted-psp (which is required for core Kubernetes functionality), edit the policy with the command:

kubectl edit podsecuritypolicy policyname
Where policyname is the name of the policy

Review the runAsUser, supplementalGroups, and fsGroup sections of the policy.

If any of these sections are missing, this is a finding.

If the rule within the runAsUser section is not set to "MustRunAsNonRoot", this is a finding.

If the ranges within the supplementalGroups section has min set to "0" or min is missing, this is a finding.

If the ranges within the fsGroup section have a min set to "0" or the min is missing, this is a finding.

If using RKE2 v1.25 or newer:

On each controlplane node, validate that the file "/etc/rancher/rke2/rke2-pss.yaml" exists and the default configuration settings match the following:

    defaults:
      audit: restricted
      audit-version: latest
      enforce: restricted
      enforce-version: latest
      warn: restricted
      warn-version: latest

If the configuration file differs from the above, this is a finding.'
  desc 'fix', %q(If using RKE2 v1.24 or older:

On each Control Plane node, create the following policy to a file called restricted.yml.

apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
name: restricted
annotations:
seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'docker/default,runtime/default'
apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
seccomp.security.alpha.kubernetes.io/defaultProfileName: 'runtime/default'
apparmor.security.beta.kubernetes.io/defaultProfileName: 'runtime/default'
spec:
privileged: false
#Required to prevent escalations to root.
allowPrivilegeEscalation: false
#This is redundant with non-root + disallow privilege escalation,
# but we can provide it for defense in depth.
requiredDropCapabilities:
- ALL
# Allow core volume types.
volumes:
- 'configMap'
- 'emptyDir'
- 'projected'
- 'secret'
- 'downwardAPI'
# Assume that persistentVolumes set up by the cluster admin are safe to use.
- 'persistentVolumeClaim'
hostNetwork: false
hostIPC: false
hostPID: false
runAsUser:
# Require the container to run without root privileges.
rule: 'MustRunAsNonRoot'
seLinux:
# This policy assumes the nodes are using AppArmor rather than SELinux.
rule: 'RunAsAny'
supplementalGroups:
rule: 'MustRunAs'
ranges:
# Forbid adding the root group.
- min: 1
max: 65535
fsGroup:
rule: 'MustRunAs'
ranges:
# Forbid adding the root group.
- min: 1
max: 65535
readOnlyRootFilesystem: false

To implement the policy, run the command:

kubectl create -f restricted.yml"

If using RKE v1.25 or newer:

On each Control Plane node, create the file "/etc/rancher/rke2/rke2-pss.yaml" and add the following content:

apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1beta1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "restricted"
      enforce-version: "latest"
      audit: "restricted"
      audit-version: "latest"
      warn: "restricted"
      warn-version: "latest"
    exemptions:
      usernames: []
      runtimeClasses: []
      namespaces: [kube-system, cis-operator-system, tigera-operator]

Ensure the namespace exemptions contain only namespaces requiring access to capabilities outside of the restricted settings above.

Once the file is created, restart the Control Plane nodes with:

systemctl restart rke2-server)
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58055r918245_chk'
  tag severity: 'medium'
  tag gid: 'V-254571'
  tag rid: 'SV-254571r918260_rule'
  tag stig_id: 'CNTR-R2-001130'
  tag gtitle: 'SRG-APP-000340-CTR-000770'
  tag fix_id: 'F-58004r918246_fix'
  tag satisfies: ['SRG-APP-000340-CTR-000770', 'SRG-APP-000342-CTR-000775']
  tag 'documentable'
  tag cci: ['CCI-002233', 'CCI-002235']
  tag nist: ['AC-6 (8)', 'AC-6 (10)']
end
