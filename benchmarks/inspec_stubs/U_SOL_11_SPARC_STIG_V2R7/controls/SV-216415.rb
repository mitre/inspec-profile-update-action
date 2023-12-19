control 'SV-216415' do
  title 'The operating system must use cryptographic mechanisms to protect the integrity of audit information.'
  desc 'Protection of audit records and audit data is of critical importance. Cryptographic mechanisms are the industry established standard used to protect the integrity of audit data.'
  desc 'check', 'The Audit Configuration and the Audit Control profiles are required.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine if audit log encryption is required by your organization. If not required, this check does not apply.

Determine where the audit logs are stored and whether the file system is encrypted.

# pfexec auditconfig -getplugin audit_binfile

The p_dir attribute lists the location of the audit log filesystem. 

The default location for Solaris 11.1 is /var/audit. /var/audit is a link to /var/share/audit which, by default, is mounted on rpool/VARSHARE.

Determine if this is encrypted:

# zfs get encryption rpool/VARSHARE

If the file system where audit logs are stored reports "encryption off", this is a finding.'
  desc 'fix', 'The ZFS File System Management and ZFS Storage Management profiles are required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

The Audit Configuration and the Audit Control profiles are required.

If necessary, create a new ZFS pool to store the encrypted audit logs.

# pfexec zpool create auditp mirror [device] [device]

Create an encryption key:

# pktool genkey keystore=file outkey=/[filename] keytype=aes keylen=256

Create a new file system to store the audit logs with encryption enabled. Use the file name created in the previous step as the keystore.

# pfexec zfs create -o encryption=aes-256-ccm -o keysource=raw,file:///[filename] -o compression=on -o mountpoint=/audit auditp/auditf

Configure auditing to use this encrypted directory.

# pfexec auditconfig -setplugin audit_binfile p_dir=/audit/

Refresh the audit service for the setting to be applied:

# pfexec audit -s'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17651r371333_chk'
  tag severity: 'low'
  tag gid: 'V-216415'
  tag rid: 'SV-216415r603267_rule'
  tag stig_id: 'SOL-11.1-060180'
  tag gtitle: 'SRG-OS-000216'
  tag fix_id: 'F-17649r371334_fix'
  tag 'documentable'
  tag legacy: ['SV-61017', 'V-48145']
  tag cci: ['CCI-001350']
  tag nist: ['AU-9 (3)']
end
