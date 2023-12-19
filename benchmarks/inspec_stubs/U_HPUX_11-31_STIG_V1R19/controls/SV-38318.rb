control 'SV-38318' do
  title 'The system must require authentication upon booting into single-user and maintenance modes.'
  desc 'Single user mode access must be strictly limited to privileged users. The ability to boot to single user mode allows a malicious user the opportunity to modify, compromise, or otherwise damage the system.'
  desc 'check', 'Check the /tcb/files/auth/system/default entry.
# grep “:d_boot_authenticate” /tcb/files/auth/system/default

If the returned entry looks like “:d_boot_authenticate@:”, single user boot authentication is disabled, and this is a finding.

For SMSE:
Check the setting for BOOT_AUTH is set to N=1.
# grep BOOT_AUTH /etc/default/security /var/adm/userdb/*

If BOOT_AUTH=0, then single user boot authentication is disabled, and this is a finding.'
  desc 'fix', 'For Trusted Mode:
If single user boot authentication is disabled, use the System Administration Manager (SAM) or the System Management Homepage (SMH) to enable single user boot (for root only) authentication.

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the attribute. See the below example:
BOOT_AUTH=1

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor."'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36228r2_chk'
  tag severity: 'medium'
  tag gid: 'V-756'
  tag rid: 'SV-38318r2_rule'
  tag stig_id: 'GEN000020'
  tag gtitle: 'GEN000020'
  tag fix_id: 'F-31487r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
