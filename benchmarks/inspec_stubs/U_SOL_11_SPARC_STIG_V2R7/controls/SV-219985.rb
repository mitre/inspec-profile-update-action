control 'SV-219985' do
  title 'The operating system must protect the audit records resulting from non-local accesses to privileged accounts and the execution of privileged functions.'
  desc 'Protection of audit records and audit data is of critical importance. Care must be taken to ensure privileged users cannot circumvent audit protections put in place. Auditing might not be reliable when performed by an operating system which the user being audited has privileged access to. The privileged user could inhibit auditing or directly modify audit records. To prevent this from occurring, privileged access shall be further defined between audit-related privileges and other privileges, thus limiting the users with audit-related privileges.'
  desc 'check', 'The audit configuration profile is required. 

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine the location of the local audit trail files.

# auditconfig -getplugin audit_binfile
Plugin: audit_binfile (active)
Attributes: p_dir=/var/audit;p_fsize=4M;p_minfree=1;"

In this example, the audit files can be found in /var/audit. Check that the permissions on the audit files are 640 (rw- r-- --) or less permissive.

# ls -al /var/audit

# ls -l /var/audit/*

If the permissions are more permissive than 640, this is a finding.

Note:  The default Solaris 11 location for /var/audit is a link to /var/share/audit.'
  desc 'fix', 'The root role is required.

Determine the location of the local audit trail files.

# pfexec auditconfig -getplugin audit_binfile
Plugin: audit_binfile (active)
Attributes: p_dir=/var/audit;p_fsize=4M;p_minfree=1

In this example, the audit files can be found in /var/audit.

Change the permissions on the audit trail files and the audit directory.

# chmod 640 /var/share/audit/*

# chmod 750 /var/share/audit

Note:  The default Solaris 11 location for /var/audit is a link to /var/share/audit.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-21695r371408_chk'
  tag severity: 'medium'
  tag gid: 'V-219985'
  tag rid: 'SV-219985r854544_rule'
  tag stig_id: 'SOL-11.1-070250'
  tag gtitle: 'SRG-OS-000327'
  tag fix_id: 'F-21694r371409_fix'
  tag 'documentable'
  tag legacy: ['V-48031', 'SV-60903']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
