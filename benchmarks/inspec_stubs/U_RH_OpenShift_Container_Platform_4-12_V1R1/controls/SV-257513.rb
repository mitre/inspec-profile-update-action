control 'SV-257513' do
  title 'OpenShift RBAC access controls must be enforced.'
  desc 'Controlling and limiting users access to system services and resources is key to securing the platform and limiting the intentional or unintentional compromising of the system and its services. OpenShift provides a robust RBAC policy system that allows for authorization policies to be as detailed as needed. Additionally, there are two layers of RBAC policies. The first is Cluster RBAC policies which administrators can control who has what access to cluster level services. The other is Local RBAC policies, which allow project developers/administrators to control what level of access users have to a given project or namespace.

OpenShift provides a set of default roles out of the box, and additional roles may be added as needed. Each role has a set of rules controlling what access that role may have, and users and/or groups may be bound to one or more roles. The cluster-admin cluster level RBAC role has complete super admin privileges and it is a required role for select cluster administrators to have.

The OpenShift Container Platform includes a built-in image registry. The primary purpose is to allow users to create, import, and generally manage images running in the cluster. This registry is integrated with the authentication and authorization (RBAC) services on the cluster.

Restricting access permissions and providing access only to the necessary components and resources within the OpenShift environment reduces the potential impact of security breaches and unauthorized activities.

'
  desc 'check', 'The administrator must verify that OpenShift is configured with the necessary RBAC access controls.

Review the RBAC configuration.

As the cluster-admin, view the cluster roles and their associated rule sets by executing the following:

oc describe clusterrole.rbac

Now, view the current set of cluster role bindings, which shows the users and groups that are bound to various roles by executing the following:

oc describe clusterrolebinding.rbac

Local roles and bindings can be determined by executing the following:

oc describe rolebinding.rbac

If these results show users with privileged access that do not require that access, this is a finding.'
  desc 'fix', 'If users or groups exist that are bound to roles they must not have, modify the user or group permissions using the following cluster and local role binding commands:

Remove a user from a Cluster RBAC role by executing the following:

oc adm policy remove-cluster-role-from-user <role> <username>

Remove a group from a Cluster RBAC role by executing the following:

oc adm policy remove-cluster-role-from-group <role> <groupname>

Remove a user from a Local RBAC role by executing the following:

oc adm policy remove-role-from-user <role> <username>

Remove a group from a Local RBAC role by executing the following:

oc adm policy remove-role-from-group <role> <groupname>
 
Note: For additional information, refer to https://docs.openshift.com/container-platform/4.8/authentication/using-rbac.html.'
  impact 0.7
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61248r921480_chk'
  tag severity: 'high'
  tag gid: 'V-257513'
  tag rid: 'SV-257513r921482_rule'
  tag stig_id: 'CNTR-OS-000090'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag fix_id: 'F-61172r921481_fix'
  tag satisfies: ['SRG-APP-000033-CTR-000090', 'SRG-APP-000033-CTR-000095', 'SRG-APP-000033-CTR-000100', 'SRG-APP-000133-CTR-000290', 'SRG-APP-000133-CTR-000295', 'SRG-APP-000133-CTR-000300', 'SRG-APP-000133-CTR-000305', 'SRG-APP-000133-CTR-000310', 'SRG-APP-000148-CTR-000350', 'SRG-APP-000153-CTR-000375', 'SRG-APP-000340-CTR-000770', 'SRG-APP-000378-CTR-000880', 'SRG-APP-000378-CTR-000885', 'SRG-APP-000378-CTR-000890', 'SRG-APP-000380-CTR-000900', 'SRG-APP-000386-CTR-000920']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-000764', 'CCI-000770', 'CCI-001499', 'CCI-001774', 'CCI-001812', 'CCI-001813', 'CCI-002235']
  tag nist: ['AC-3', 'IA-2', 'IA-2 (5)', 'CM-5 (6)', 'CM-7 (5) (b)', 'CM-11 (2)', 'CM-5 (1) (a)', 'AC-6 (10)']
end
