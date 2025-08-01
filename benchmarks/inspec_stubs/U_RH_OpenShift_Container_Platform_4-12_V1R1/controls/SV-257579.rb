control 'SV-257579' do
  title 'OpenShift must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Audit records provide valuable information for security monitoring and intrusion detection. By generating audit logs for logon attempts, OpenShift enables administrators and security teams to track and investigate any unauthorized or suspicious access attempts. These records serve as a vital source of information for detecting and responding to potential security breaches or unauthorized logon activities.

Generating audit records for logon attempts supports user accountability. Audit logs provide a trail of logon activities, allowing administrators to attribute specific logon events to individual users or entities. This promotes accountability and helps in identifying any unauthorized access attempts or suspicious behavior by specific users.

By monitoring logon activity logs, administrators and security teams can identify unusual or suspicious patterns of logon attempts. Forensic analysts can examine these records to reconstruct the timeline of logon activities and determine the scope and nature of the incident.'
  desc 'check', %q(Verify that logons are audited by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n ""$HOSTNAME ""; grep ""logins"" /etc/audit/audit.rules /etc/audit/rules.d/*' 2>/dev/null; done

The output will look similar to:

node-name /etc/audit/<file>:-w /var/run/faillock -p wa -k logins
/etc/audit/<file>:-w /var/log/lastlog -p wa -k logins

If the two rules above are not found on each node, this is a finding.)
  desc 'fix', 'Apply the machine config to audit logons by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-logon-attempts-rules-$mcpool
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
      - contents:
          source: data:,-w%20/etc/sudoers.d/%20-p%20wa%20-k%20actions%0A-w%20/etc/sudoers%20-p%20wa%20-k%20actions%0A
        mode: 0644
        path: /etc/audit/rules.d/75-audit-sysadmin-actions.rules
        overwrite: true
      - contents:
          source: data:,-w%20/etc/group%20-p%20wa%20-k%20audit_rules_usergroup_modification%0A
        mode: 0644
        path: /etc/audit/rules.d/30-etc_group_usergroup_modification.rules
        overwrite: true
      - contents:
          source: data:,-w%20/etc/gshadow%20-p%20wa%20-k%20audit_rules_usergroup_modification%0A
        mode: 0644
        path: /etc/audit/rules.d/30-etc_gshadow_usergroup_modification.rules
        overwrite: true
      - contents:
          source: data:,-w%20/etc/security/opasswd%20-p%20wa%20-k%20audit_rules_usergroup_modification%0A
        mode: 0644
        path: /etc/audit/rules.d/30-etc_security_opasswd_usergroup_modification.rules
        overwrite: true
      - contents:
          source: data:,-w%20/etc/passwd%20-p%20wa%20-k%20audit_rules_usergroup_modification%0A
        mode: 0644
        path: /etc/audit/rules.d/30-etc_passwd_usergroup_modification.rules
        overwrite: true
      - contents:
          source: data:,-w%20/etc/shadow%20-p%20wa%20-k%20audit_rules_usergroup_modification%0A
        mode: 0644
        path: /etc/audit/rules.d/30-etc_shadow_usergroup_modification.rules
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61314r921678_chk'
  tag severity: 'medium'
  tag gid: 'V-257579'
  tag rid: 'SV-257579r921680_rule'
  tag stig_id: 'CNTR-OS-000970'
  tag gtitle: 'SRG-APP-000503-CTR-001275'
  tag fix_id: 'F-61238r921679_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
