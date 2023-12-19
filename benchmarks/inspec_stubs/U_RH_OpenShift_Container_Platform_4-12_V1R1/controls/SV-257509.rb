control 'SV-257509' do
  title 'OpenShift must automatically audit account creation.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create a new account. Auditing account creation is one method for mitigating this risk.

A comprehensive account management process will ensure an audit trail documents the creation of application user accounts and, as required, notifies administrators and/or application owners exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', %q(Verify Red Hat Enterprise Linux CoreOS (RHCOS) generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/shadow".

Logging on as administrator, check the auditing rules in "/etc/audit/audit.rules" by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME: "; grep /etc/shadow /etc/audit/audit.rules /etc/audit/rules.d/*'; done

(Example output:
-w /etc/shadow -p wa -k identity)

If the command does not return a line, or the line is commented out, this is a finding.)
  desc 'fix', 'Apply the machine config using the following command:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 75-account-modifications-rules-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
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
  tag check_id: 'C-61244r921468_chk'
  tag severity: 'medium'
  tag gid: 'V-257509'
  tag rid: 'SV-257509r921470_rule'
  tag stig_id: 'CNTR-OS-000050'
  tag gtitle: 'SRG-APP-000026-CTR-000070'
  tag fix_id: 'F-61168r921469_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
