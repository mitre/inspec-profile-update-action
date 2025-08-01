control 'SV-257517' do
  title 'OpenShift must generate audit records for all DOD-defined auditable events within all components in the platform.'
  desc 'The OpenShift Platform supports three audit levels: Default, WriteRequestBodies, and AllRequestBodies. The identities of the users are logged for all three audit levels log level. The WriteRequestBodies will log the metadata and the request body for any create, update, or patch request. The AllRequestBodies will log the metadata and the request body for all read and write requests. As this generates a significant number of logs, this level is only to be used as needed. To capture sufficient data to investigate an issue, it is required to set the audit level to WriteRequestBodies.

For more detailed documentation on what is being logged, refer to https://docs.openshift.com/container-platform/4.8/security/audit-log-view.html.

'
  desc 'check', "To determine at what level the OpenShift audit policy logging verbosity is configured, as a cluster-administrator:execute the following command:

oc get apiserver.config.openshift.io/cluster -ojsonpath='{.spec.audit.profile}'

If the output from the options does not return WriteRequestBodies or AllRequestBodies, this is a finding."
  desc 'fix', %q(As the cluster administrator, update the APIServer.config.openshift.io/cluster object to set the profile to the defined level of detail. For example, to configure the profile to WriteRequestBodies, meaning that all write requests to any API server object are logged in their entirety, by executing the following:

oc patch apiserver.config.openshift.io/cluster --type=merge -p '{"spec": {"audit": {"profile": "WriteRequestBodies"}}}')
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61252r921492_chk'
  tag severity: 'medium'
  tag gid: 'V-257517'
  tag rid: 'SV-257517r921494_rule'
  tag stig_id: 'CNTR-OS-000150'
  tag gtitle: 'SRG-APP-000089-CTR-000150'
  tag fix_id: 'F-61176r921493_fix'
  tag satisfies: ['SRG-APP-000089-CTR-000150', 'SRG-APP-000090-CTR-000155', 'SRG-APP-000101-CTR-000205', 'SRG-APP-000510-CTR-001310', 'SRG-APP-000516-CTR-000790']
  tag 'documentable'
  tag cci: ['CCI-000135', 'CCI-000169', 'CCI-000171', 'CCI-000172', 'CCI-000366']
  tag nist: ['AU-3 (1)', 'AU-12 a', 'AU-12 b', 'AU-12 c', 'CM-6 b']
end
