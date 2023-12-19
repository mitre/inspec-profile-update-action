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
  desc 'check', 'On the Server Node, run the command:

kubectl get podsecuritypolicy

For any pod security policies listed, with the exception of system-unrestricted-psp (which is required for core Kubernetes functionality), edit the policy with the command:

kubectl edit podsecuritypolicy policyname
Where policyname is the name of the policy

Review the runAsUser, supplementalGroups and fsGroup sections of the policy.

If any of these sections are missing, this is a finding.

If the rule within the runAsUser section is not set to "MustRunAsNonRoot" this is a finding.

If the ranges within the supplementalGroups section has min set to "0" or min is missing, this is a finding.

If the ranges within the fsGroup section has a min set to "0" or the min is missing, this is a finding.'
  desc 'fix', "From the Server node, save the following policy to a file called restricted.yml.
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'docker/default,runtime/default'
    apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
    seccomp.security.alpha.kubernetes.io/defaultProfileName:  'runtime/default'
    apparmor.security.beta.kubernetes.io/defaultProfileName:  'runtime/default'
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
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58055r894465_chk'
  tag severity: 'medium'
  tag gid: 'V-254571'
  tag rid: 'SV-254571r894467_rule'
  tag stig_id: 'CNTR-R2-001130'
  tag gtitle: 'SRG-APP-000340-CTR-000770'
  tag fix_id: 'F-58004r894466_fix'
  tag satisfies: ['SRG-APP-000340-CTR-000770', 'SRG-APP-000342-CTR-000775']
  tag 'documentable'
  tag cci: ['CCI-002233', 'CCI-002235']
  tag nist: ['AC-6 (8)', 'AC-6 (10)']
end
