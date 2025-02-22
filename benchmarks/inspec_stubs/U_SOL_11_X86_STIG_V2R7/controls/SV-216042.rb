control 'SV-216042' do
  title 'The operating system must protect audit information from unauthorized access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. 

To ensure the veracity of audit data, the operating system must protect audit information from unauthorized access.

'
  desc 'check', 'The root role is required.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Check that the directory storing the audit files is owned by root and has permissions 750 or less.

Note: By default in Solaris 11.1, /var/audit is a link to /var/share/audit which is mounted on rpool/VARSHARE.

Determine the location of the audit trail files
# pfexec auditconfig -getplugin audit_binfile

The output will appear in this form:

Plugin: audit_binfile (active)
Attributes: p_dir=/var/audit;p_fsize=0;p_minfree=1

The p_dir attribute defines the location of the audit directory.
# ls -ld /var/share/audit

Check the audit directory is owned by root, group is root, and permissions are 750 (rwx r-- ---) or less. If the permissions are excessive, this is a finding.'
  desc 'fix', 'Note: By default in Solaris 11.1, /var/audit is a link to /var/share/audit which is mounted on rpool/VARSHARE.

The root role is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Determine the location of the audit trail files
# pfexec auditconfig -getplugin audit_binfile|

The output will appear in this form:

Plugin: audit_binfile (active)
Attributes: p_dir=/var/audit;p_fsize=0;p_minfree=1

The p_dir attribute defines the location of the audit directory.

# chown root [directory]
# chgrp root [directory]
# chmod 750 [directory]'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-36490r603073_chk'
  tag severity: 'medium'
  tag gid: 'V-216042'
  tag rid: 'SV-216042r603268_rule'
  tag stig_id: 'SOL-11.1-010440'
  tag gtitle: 'SRG-OS-000057'
  tag fix_id: 'F-36454r603074_fix'
  tag satisfies: ['SRG-OS-000057', 'SRG-OS-000058', 'SRG-OS-000059']
  tag 'documentable'
  tag legacy: ['V-47869', 'SV-60741']
  tag cci: ['CCI-000162', 'CCI-000163']
  tag nist: ['AU-9 a', 'AU-9 a']
end
