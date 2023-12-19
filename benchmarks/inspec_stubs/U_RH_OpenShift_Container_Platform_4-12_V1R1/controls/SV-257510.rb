control 'SV-257510' do
  title 'OpenShift must automatically audit account modification.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to modify an existing account. Auditing of account modifications is one method for mitigating this risk.

A comprehensive account management process will ensure an audit trail documents the creation of application user accounts and, as required, notifies administrators and/or application owners exists. Such a process greatly reduces the risk that accounts will be surreptitiously modified and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to offload those access control functions and focus on core application features and functionality.'
  desc 'check', %q(Verify for each of the files that contain account information the system is configured to emit an audit event in case of a write by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; for f in /etc/passwd /etc/group /etc/gshadow /etc/security/opasswd /etc/shadow /etc/sudoers /etc/sudoers.d/; do grep -q "\-w $f \-p wa \-k" /etc/audit/audit.rules || echo "rule for $f not found"; done' 2>/dev/null; done

If for any of the files a line saying "rule for $filename not found" is printed, this is a finding.)
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
  tag check_id: 'C-61245r921471_chk'
  tag severity: 'medium'
  tag gid: 'V-257510'
  tag rid: 'SV-257510r921473_rule'
  tag stig_id: 'CNTR-OS-000060'
  tag gtitle: 'SRG-APP-000027-CTR-000075'
  tag fix_id: 'F-61169r921472_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
