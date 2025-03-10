control 'SV-257525' do
  title 'OpenShift must use internal system clocks to generate audit record time stamps.'
  desc 'Knowing when a sequence of events for an incident occurred is crucial to understand what may have taken place. Without a common clock, the components generating audit events could be out of synchronization and would then present a picture of the event that is warped and corrupted. To give a clear picture, it is important that the container platform and its components use a common internal clock.'
  desc 'check', %q(Verify the chronyd service is enabled and active by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; systemctl is-enabled chronyd.service; systemctl is-active chronyd.service' 2>/dev/null; done

If the auditd service is not "enabled" and "active", this is a finding.)
  desc 'fix', 'Apply the machine config to use internal system clocks for audit records by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 80-chronyd-service-enable-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    systemd:
      units:
      - name: chronyd.service
        enabled: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61260r921516_chk'
  tag severity: 'medium'
  tag gid: 'V-257525'
  tag rid: 'SV-257525r921518_rule'
  tag stig_id: 'CNTR-OS-000230'
  tag gtitle: 'SRG-APP-000116-CTR-000235'
  tag fix_id: 'F-61184r921517_fix'
  tag 'documentable'
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
