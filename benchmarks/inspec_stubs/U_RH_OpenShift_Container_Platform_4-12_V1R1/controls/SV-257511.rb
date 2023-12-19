control 'SV-257511' do
  title 'OpenShift must generate audit rules to capture account related actions.'
  desc 'Account management actions, such as creation, modification, disabling, removal, and enabling are important changes within the system. 

When management actions are modified, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to disable authorized accounts to disrupt services or prevent the implementation of countermeasures. In the event of a security incident or policy violation, having detailed audit logs for account creation, modification, disabling, removal, and enabling actions is crucial for incident response and forensic investigations. These logs provide a trail of activities that can be analyzed to determine the cause, impact, and scope of the incident, aiding in the investigation and remediation process.

'
  desc 'check', %q(Verify the audit rules capture account creation, modification, disabling, removal, and enabling actions by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -e user-modify -e group-modify -e audit_rules_usergroup_modification /etc/audit/rules.d/* /etc/audit/audit.rules' 2>/dev/null; done

Confirm the following rules exist on each node:

-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification

If the above rules are not listed on each node, this is a finding.)
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
  tag check_id: 'C-61246r921474_chk'
  tag severity: 'medium'
  tag gid: 'V-257511'
  tag rid: 'SV-257511r921476_rule'
  tag stig_id: 'CNTR-OS-000070'
  tag gtitle: 'SRG-APP-000028-CTR-000080'
  tag fix_id: 'F-61170r921475_fix'
  tag satisfies: ['SRG-APP-000028-CTR-000080', 'SRG-APP-000291-CTR-000675', 'SRG-APP-000292-CTR-000680', 'SRG-APP-000293-CTR-000685', 'SRG-APP-000294-CTR-000690', 'SRG-APP-000319-CTR-000745', 'SRG-APP-000320-CTR-000750', 'SRG-APP-000509-CTR-001305']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-001404', 'CCI-001683', 'CCI-001684', 'CCI-001685', 'CCI-001686', 'CCI-002130', 'CCI-002132']
  tag nist: ['AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
