control 'SV-257581' do
  title 'OpenShift audit records must record user access start and end times.'
  desc 'OpenShift must generate audit records showing start and end times for users and services acting on behalf of a user accessing the registry and keystore. These components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.'
  desc 'check', %q(Verify the Red Hat Enterprise Linux CoreOS (RHCOS) is configured to generate audit records showing starting and ending times for user access by executing the following:
 
for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -e "-k session" /etc/audit/audit.rules' 2>/dev/null; done

Confirm the following rules exist on each node:

 -w /var/log/btmp -p wa -k session
-w /var/log/utmp -p wa -k session

If the above rules are not listed on each node, this is a finding.)
  desc 'fix', 'Apply the machine config for user access times by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-session-start-end-time-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,-w%20/var/log/btmp%20-p%20wa%20-k%20session%0A
        mode: 0644
        path: /etc/audit/rules.d/75-var_log_btmp_write_events.rules
        overwrite: true
      - contents:
          source: data:,-w%20/var/log/utmp%20-p%20wa%20-k%20session%0A
        mode: 0644
        path: /etc/audit/rules.d/75-var_log_utmp_write_events.rules
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61316r921684_chk'
  tag severity: 'medium'
  tag gid: 'V-257581'
  tag rid: 'SV-257581r921686_rule'
  tag stig_id: 'CNTR-OS-000990'
  tag gtitle: 'SRG-APP-000505-CTR-001285'
  tag fix_id: 'F-61240r921685_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
