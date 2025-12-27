control 'SV-257534' do
  title 'OpenShift must prevent unauthorized changes to logon UIDs.'
  desc 'Logon UIDs are used to uniquely identify and authenticate users within the system. By preventing unauthorized changes to logon UIDs, OpenShift ensures that user identities remain consistent and accurate. This helps maintain the integrity of user accounts and ensures that users can be properly authenticated and authorized for their respective resources and actions.

User accounts and associated logon UIDs are important for security monitoring, auditing, and accountability purposes. By preventing unauthorized changes to logon UIDs, OpenShift ensures that actions performed by users can be accurately traced and attributed to the correct user account. This helps with incident investigation, compliance requirements, and maintaining overall system security.'
  desc 'check', %q(Verify the audit system prevents unauthorized changes to logon UIDs by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -i immutable /etc/audit/audit.rules || echo "not found"' 2>/dev/null; done

If the login UIDs are not set to be immutable by adding the "--loginuid-immutable" option to the "/etc/audit/audit.rules", this is a finding.)
  desc 'fix', 'Apply the machine config to prevent changes to logon UIDs by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
 echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 11-loginuid-rules-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,%23%23%20Make%20the%20loginuid%20immutable.%20This%20prevents%20tampering%20with%20the%20auid.%0A--loginuid-immutable%0A
        mode: 0644
        path: /etc/audit/rules.d/11-loginuid.rules
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61269r921543_chk'
  tag severity: 'medium'
  tag gid: 'V-257534'
  tag rid: 'SV-257534r921545_rule'
  tag stig_id: 'CNTR-OS-000320'
  tag gtitle: 'SRG-APP-000121-CTR-000255'
  tag fix_id: 'F-61193r921544_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
