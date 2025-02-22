control 'SV-257535' do
  title 'OpenShift must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'List the users and groups who have permission to view the cluster logging configuration by executing the following two commands:

oc policy who-can view ClusterLogging -n openshift-logging

oc policy who-can view ClusterLoggingForwarder -n openshift-logging

Review the list of users and groups who have view access to the cluster logging resources. If any user or group listed must not have access to view the cluster logging resources, this is a finding.'
  desc 'fix', 'Remove view permissions from any unauthorized user or group by performing one or more of the following commands.

Remove role from user by executing the following:

oc adm policy remove-role-from-user <ROLE> <USER> -n openshift-logging

Remove role from group by executing the following:

oc adm policy remove-role-from-group <ROLE> <GROUP> -n openshift-logging

Remove cluster role from user by executing the following:
oc adm policy remove-cluster-role-from-user <CLUSTER_ROLE> <USER> -n openshift-logging

Remove cluster role from group by executing the following:

oc adm policy remove-cluster-role-from-group <CLUSTER_ROLE> <GROUP> -n openshift-logging

Note: ROLE/CLUSTER_ROLE is the role granting user view permission to resources in openshift-logging namespace.'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61270r921546_chk'
  tag severity: 'medium'
  tag gid: 'V-257535'
  tag rid: 'SV-257535r921548_rule'
  tag stig_id: 'CNTR-OS-000330'
  tag gtitle: 'SRG-APP-000121-CTR-000255'
  tag fix_id: 'F-61194r921547_fix'
  tag satisfies: ['SRG-APP-000121-CTR-000255', 'SRG-APP-000122-CTR-000260', 'SRG-APP-000123-CTR-000265']
  tag 'documentable'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
end
