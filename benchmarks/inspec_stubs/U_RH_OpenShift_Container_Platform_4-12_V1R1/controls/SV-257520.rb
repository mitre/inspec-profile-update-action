control 'SV-257520' do
  title 'All audit records must identify what type of event has occurred within OpenShift.'
  desc 'Within the container platform, audit data can be generated from any of the deployed container platform components. This audit data is important when there are issues such as security incidents that must be investigated. Identifying the type of event in audit records helps classify and categorize different activities or actions within OpenShift. This classification allows for easier analysis, reporting, and filtering of audit logs based on specific event types. It helps distinguish between user actions, system events, policy violations, or security incidents, providing a clearer understanding of the activities occurring within the platform.

'
  desc 'check', %q(Verify the audit service is enabled and active by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; systemctl is-enabled auditd.service; systemctl is-active auditd.service' 2>/dev/null; done

If the auditd service is not "enabled" and "active" this is a finding.)
  desc 'fix', 'Apply the machine config setting auditd to active and enabled by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 80-auditd-service-enable-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    systemd:
      units:
      - name: auditd.service
        enabled: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61255r921501_chk'
  tag severity: 'medium'
  tag gid: 'V-257520'
  tag rid: 'SV-257520r921503_rule'
  tag stig_id: 'CNTR-OS-000180'
  tag gtitle: 'SRG-APP-000095-CTR-000170'
  tag fix_id: 'F-61179r921502_fix'
  tag satisfies: ['SRG-APP-000095-CTR-000170', 'SRG-APP-000409-CTR-000990', 'SRG-APP-000508-CTR-001300', 'SRG-APP-000510-CTR-001310']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 c', 'MA-4 (1) (a)']
end
