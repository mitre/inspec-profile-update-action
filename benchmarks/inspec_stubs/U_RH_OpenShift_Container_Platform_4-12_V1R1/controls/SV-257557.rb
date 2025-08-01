control 'SV-257557' do
  title 'Container images instantiated by OpenShift must execute using least privileges.'
  desc 'Container images running on OpenShift must support running as any arbitrary UID. OpenShift will then assign a random, nonprivileged UID to the running container instance. This avoids the risk from containers running with specific UIDs that could map to host service accounts, or an even greater risk of running as root level service.

OpenShift uses the default security context constraints (SCC), restricted, to prevent containers from running as root or other privileged user IDs. Pods must be configured to use an SCC policy that allows the container to run as a specific UID, including root(0) when approved. Only a cluster administrator may grant the change of an SCC policy.

https://docs.openshift.com/container-platform/4.8/openshift_images/create-images.html#images-create-guide-openshift_create-images

'
  desc 'check', %q(Check SCC:

1. Identify any SCC policy that allows containers to access the host network or filesystem resources, or allows privileged containers or where runAsUser is not MustRunAsRange by executing the following:

oc get scc -ojson | jq '.items[]|select(.allowHostIPC or .allowHostPID or .allowHostPorts or .allowHostNetwork or .allowHostDirVolumePlugin or .allowPrivilegedContainer or .runAsUser.type != "MustRunAsRange" )|.metadata.name,{"Group:":.groups},{"User":.users}'

For each SCC listed, if any of those users or groups are anything other than the following, this is a finding:

  * system:cluster-admins
  * system:nodes
  * system:masters
  * system:admin
  * system:serviceaccount:openshift-infra:build-controller
  * system:serviceaccount:openshift-infra:pv-recycler-controller
  * system:serviceaccount:openshift-machine-api:machine-api-termination-handler

The group "system:authenticated" is the default group for any authenticated user, this group should only be associated with the restricted profile. If this group is listed under any other SCC Policy, or the restricted SCC policy has been altered to allow any of the nonpermitted actions, this is a finding.

2. Determine if there are any cluster roles or local roles that allow the use of use of nonpermitted SCC policies. The following commands will print the role's name and namespace, followed by a list of resource names and if that resource is an SCC.

oc get clusterrole.rbac -ojson | jq -r '.items[]|select(.rules[]?|select( (.apiGroups[]? == ("security.openshift.io")) and (.resources[]? == ("securitycontextconstraints")) and (.verbs[]? == ("use"))))|.metadata.name,{"scc":(.rules[]?|select((.resources[]? == ("securitycontextconstraints"))).resourceNames[]?)}'

oc get role.rbac --all-namespaces -ojson | jq -r '.items[]|select(.rules[]?|select( (.apiGroups[]? == ("security.openshift.io")) and (.resources[]? == ("securitycontextconstraints")) and (.verbs[]? == ("use"))))|.metadata.name,{"scc":(.rules[]?|select((.resources[]? == ("securitycontextconstraints"))).resourceNames[]?)}'

Excluding platform specific roles, identify any roles that allow use of nonpermitted SCC policies. For example, the follow output shows that the role 'examplePrivilegedRole' allows use of the 'privileged' SCC.

examplePrivilegedRole
{
  "scc": "privileged"
}

3. Determine if there are any role bindings to cluster or local roles that allow use of nonpermitted SCCs by executing the following:

oc get clusterrolebinding.rbac -ojson | jq -r '.items[]|select(.roleRef.kind == ("ClusterRole","Role") and .roleRef.name == (<CLUSTER_ROLE_LIST>))|{ "crb": .metadata.name, "roleRef": .roleRef, "subjects": .subjects}'

oc get rolebinding.rbac --all-namespaces -ojson | jq -r '.items[]|select(.roleRef.kind == ("ClusterRole","Role") and .roleRef.name == (<LOCAL_ROLE_LIST>))|{ "crb": .metadata.name, "roleRef": .roleRef, "subjects": .subjects}'

Where <CLUSTER_ROLE_LIST> and <LOCAL_ROLE_LIST> are comma-separated lists of the roles allowing use of nonpermitted SCC policies as identified above. For example:

... .roleRef.name == ("system:openshift:scc:privileged","system:openshift:scc:hostnetwork","system:openshift:scc:hostaccess") ...

Excluding any platform namespaces (kube-*,openshift-*), if there are any rolebindings to roles that are not permitted, this is a finding.)
  desc 'fix', 'For users and groups that are defined in the SCC policy, execute the following to remove the users or groups by editing the corresponding SCC policy.

oc edit scc <SCC>

The following instructions will remove the user or group from the cluster role binding for the SCC policy.

Remove user from the SCC policy binding by executing the following:

oc adm policy remove-scc-from-user <SCC> <USER>

Remove a group from the SCC policy binding by executing the following:

oc adm policy remove-scc-from-group <SCC> <GROUP>

Remove service account from the SCC policy binding by executing the following:

oc project <SERVICE_ACC_PROJECT>
oc adm policy remove-scc-from-user <SCC> -z <SERVICE_ACC>

Remove any roles that allows use of nonpermitted SCC policies (excluding platform-defined roles) by executing the following:

oc delete clusterrole.rbac <ROLE>
or
oc delete role.rbac <ROLE> -n <NAMESPACE>'
  impact 0.7
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61292r921612_chk'
  tag severity: 'high'
  tag gid: 'V-257557'
  tag rid: 'SV-257557r921614_rule'
  tag stig_id: 'CNTR-OS-000660'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag fix_id: 'F-61216r921613_fix'
  tag satisfies: ['SRG-APP-000342-CTR-000775', 'SRG-APP-000142-CTR-000330', 'SRG-APP-000243-CTR-000595']
  tag 'documentable'
  tag cci: ['CCI-000382', 'CCI-001090', 'CCI-002233']
  tag nist: ['CM-7 b', 'SC-4', 'AC-6 (8)']
end
