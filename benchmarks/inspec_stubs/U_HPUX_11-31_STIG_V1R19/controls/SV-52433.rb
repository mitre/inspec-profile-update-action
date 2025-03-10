control 'SV-52433' do
  title 'The ability to boot the system into single user mode must be restricted to root.'
  desc 'Single user mode access must be strictly limited to the privileged user root. The ability to boot to single user mode allows a malicious user the opportunity to modify, compromise, or otherwise damage the system.'
  desc 'check', 'For Trusted Mode:
Protected password database files are maintained in the /tcb/files/auth hierarchy. This directory contains other directories each named with a single letter from the alphabet. User authentication profiles are stored in these directories based on the first letter of the user account name. Next check that only root is authorized to boot into single user mode.
# grep “:u_bootauth:” /tcb/files/auth/[a-z,A-Z]/*

If any non-root users have been granted single user boot privileges, this is a finding.

For SMSE:
Check the /etc/default/security file for the following attribute(s) and attribute values:
BOOT_USERS=root (Note: BOOT_USERS attribute values are comma delimited strings).
# grep “BOOT_USERS” /etc/default/security /var/adm/userdb/*

If the BOOT_USERS attribute contains any username other than root, this is a finding.'
  desc 'fix', 'For Trusted Mode:
If single user boot authentication is disabled, use the System Administration Manager (SAM) or the System Management Homepage (SMH) to allow single user boot for root only.

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) and/or the userdbset command (/var/adm/userdb/* files) to update the attribute. See the below example:
BOOT_USERS=root

Note: Never use a text editor to modify any /var/adm/userdb database file. The database contains checksums and other binary data, and editors (vi included) do not follow the file locking conventions that are used to control access to the database.

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-47006r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40446'
  tag rid: 'SV-52433r1_rule'
  tag stig_id: 'GEN000000-HPUX0230'
  tag gtitle: 'GEN000000-HPUX0230'
  tag fix_id: 'F-45395r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
