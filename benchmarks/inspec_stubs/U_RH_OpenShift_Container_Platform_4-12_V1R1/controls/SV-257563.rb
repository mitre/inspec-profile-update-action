control 'SV-257563' do
  title 'Vulnerability scanning applications must implement privileged access authorization to all OpenShift components, containers, and container images for selected organization-defined vulnerability scanning activities.'
  desc 'OpenShift uses service accounts to provide applications running on or off the platform access to the API service using the enforced RBAC policies. Vulnerability scanning applications that need access to the container platform may use a service account to grant that access. That service account can then be bound to the appropriate role required. The highest level of access granted is the cluster-admin role. Any account bound to that role can access and modify anything on the platform. It is strongly recommended to limit the number of accounts bound to that role. Instead, there are other predefined cluster level roles that may support the scanning to, such as the view or edit cluster roles. Additionally, custom roles may be defined to tailor fit access as needed by the scanning tools.'
  desc 'check', %q(If no vulnerability scanning tool is used, this requirement is Not Applicable.

Identify the service accounts used by the vulnerability scanning tools. If the tool runs as a container on the platform, then service account information can be found in the pod details by executing the following:

(oc get pods to list pods)
oc get pod <POD_ID> -o jsonpath='{.spec.serviceAccount}{"\n"}'

If no service account exists for the vulnerability scanning tool, this is a finding.

View cluster role bindings to determine which role the service account is bound to by executing the following:

oc get clusterrolebinding -ojson | jq '.items[]|select(.subjects[]?|select(.kind == "ServiceAccount" and .name == "ingress-to-route-controller"))|{ "crb": .metadata.name, "roleRef": .roleRef, "subjects": .subjects}'

Find the role to which the service account is bound, if the service account is not bound to a cluster role, or the role does not provide sufficient access, this is a finding.)
  desc 'fix', 'If no vulnerability scanning tool is used, this requirement is Not Applicable.

Create a service if one does not already exist.

Change to the appropriate namespace by executing the following:

oc project <namespace>

Create Service Account in the Project by executing the following:

oc create sa <service_account_name>

Verify creation of the Service Account by executing the following:

oc get sa | grep  <service_account_name>

Bind to the appropriate cluster RBAC role by executing the following:

oc adm policy add-cluster-role-to-user <role_name> -z <service_account_name>

For more information, refer to the following guides:
https://docs.openshift.com/container-platform/4.8/authentication/using-rbac.html

https://docs.openshift.com/container-platform/4.8/authentication/understanding-and-creating-service-accounts.html

https://docs.openshift.com/container-platform/4.8/authentication/using-service-accounts-in-applications.html'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61298r921630_chk'
  tag severity: 'medium'
  tag gid: 'V-257563'
  tag rid: 'SV-257563r921632_rule'
  tag stig_id: 'CNTR-OS-000770'
  tag gtitle: 'SRG-APP-000414-CTR-001010'
  tag fix_id: 'F-61222r921631_fix'
  tag 'documentable'
  tag cci: ['CCI-001067']
  tag nist: ['RA-5 (5)']
end
