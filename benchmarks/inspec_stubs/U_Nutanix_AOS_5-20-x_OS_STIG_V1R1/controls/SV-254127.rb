control 'SV-254127' do
  title 'Nutanix AOS must audit all account actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.

To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.

'
  desc 'check', 'Verify Nutanix AOS is configured to audit all account creations.

Run the following command to verify account creation and modification is audited.

$ sudo auditctl -l | grep "audit_account_changes"

If the command does not return the following output, this is a finding.

-w /etc/group -p wa -k audit_account_changes
-w /etc/passwd -p wa -k audit_account_changes
-w /etc/gshadow -p wa -k audit_account_changes
-w /etc/shadow -p wa -k audit_account_changes
-w /etc/security/opasswd -p wa -k audit_account_changes'
  desc 'fix', 'Run the salt stack call to set the audit configuration to audit all account creation and modification.

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57612r846467_chk'
  tag severity: 'medium'
  tag gid: 'V-254127'
  tag rid: 'SV-254127r846469_rule'
  tag stig_id: 'NUTX-OS-000110'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-57563r846468_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130']
  tag nist: ['AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
