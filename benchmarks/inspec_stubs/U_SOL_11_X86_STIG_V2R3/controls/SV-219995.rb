control 'SV-219995' do
  title 'The operating system must allocate audit record storage capacity.'
  desc 'Proper audit storage capacity is crucial to ensuring the ongoing logging of critical events.'
  desc 'check', 'The Audit Configuration profile is required.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Review the current audit file space limitations

# pfexec auditconfig -getplugin audit_binfile
Plugin: audit_binfile (active)

The output of the command will appear in this form.

Attributes: p_dir=/var/audit;p_fsize=4M;p_minfree=2

If p_minfree is not equal to "2" of greater, this is a finding.

p_dir defines the current audit file system.

Note: By default in Solaris 11.1, /var/audit is a link to /var/share/audit which is mounted on rpool/VARSHARE.

Check that zfs compression is enabled for the audit file system.

# zfs get compression [poolname/filesystemname]

If compression is off, this is a finding.

Check that a ZFS quota is enforced for the audit filesystem.

# zfs get quota [poolname/filesystemname]

If quota is set to "none", this is a finding.

Ensure that a reservation of space is enforced on /var/share so that other users do not use up audit space.

# zfs get quota,reservation [poolname/filesystemname]

If reservation is set to "none", this is a finding.'
  desc 'fix', 'The Audit Configuration, Audit Control and ZFS File System Management profiles are required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Determine the audit system directory name:

# pfexec auditconfig -getplugin audit_binfile
Plugin: audit_binfile (active)

The output of the command will appear in this form:

Attributes: p_dir=/var/audit;p_fsize=4M;p_minfree=1;

p_dir defines the current audit file system.

Note: By default in Solaris 11.1, /var/audit is a link to /var/share/audit which is mounted on rpool/VARSHARE.

Set a minimum percentage of free space on the audit_binfile plugin to 2%.

# pfexec auditconfig -setplugin audit_binfile p_minfree=2

Restart the audit system.

# pfexec audit -s

Enable compression for the audit filesystem.

# pfexec zfs set compression=on [poolname/filesystemname]

Set a ZFS quota on the default /var/share filesystem for audit records to ensure that the root pool is not filled up with audit logs.

# pfexec zfs set quota=XXG [poolname/filesystemname]

This commands sets the quota to XX Gigabytes. This value should be based upon organizational requirements.

Set a ZFS reservation on the default /var/share filesystem for audit records to ensure that the audit file system is guaranteed a fixed amount of storage.

# pfexec zfs set reservation=XXG [poolname/filesystemname]

This commands sets the quota to XX Gigabytes. This value should be based upon organizational requirements.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-21705r372499_chk'
  tag severity: 'medium'
  tag gid: 'V-219995'
  tag rid: 'SV-219995r603268_rule'
  tag stig_id: 'SOL-11.1-010400'
  tag gtitle: 'SRG-OS-000341'
  tag fix_id: 'F-21704r372500_fix'
  tag 'documentable'
  tag legacy: ['V-47857', 'SV-60731']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
