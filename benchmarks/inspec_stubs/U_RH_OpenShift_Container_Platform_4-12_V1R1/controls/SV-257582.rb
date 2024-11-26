control 'SV-257582' do
  title 'OpenShift must generate audit records when concurrent logons from different workstations and systems occur.'
  desc 'OpenShift and its components must generate audit records for concurrent logons from workstations perform remote maintenance, runtime instances, connectivity to the container registry, and keystore. All the components must use the same standard so the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.'
  desc 'check', %q(Verify that concurrent logons are audited by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep "logins" /etc/audit/audit.rules /etc/audit/rules.d/*' 2>/dev/null; done

The output will look similar to:

node-name /etc/audit/<file>:-w /var/run/faillock -p wa -k logins
/etc/audit/<file>:-w /var/log/lastlog -p wa -k logins

If the two rules above are not found on each node, this is a finding.)
  desc 'fix', 'Apply the machine config so concurrent logons are audited by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-concurrent-logons-rules
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,-w%20/var/run/faillock%20-p%20wa%20-k%20logins%0A
        mode: 0644
        path: /etc/audit/rules.d/75-faillock_login_events.rules
        overwrite: true
      - contents:
          source: data:,-w%20/var/log/lastlog%20-p%20wa%20-k%20logins%0A
        mode: 0644
        path: /etc/audit/rules.d/75-lastlog_login_events.rules
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61317r921687_chk'
  tag severity: 'medium'
  tag gid: 'V-257582'
  tag rid: 'SV-257582r921689_rule'
  tag stig_id: 'CNTR-OS-001000'
  tag gtitle: 'SRG-APP-000506-CTR-001290'
  tag fix_id: 'F-61241r921688_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
