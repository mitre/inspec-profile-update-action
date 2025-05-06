control 'SV-37884' do
  title 'The /etc/smbpasswd file must not have an extended ACL.'
  desc 'If the permissions of the "smbpasswd" file are too permissive, it may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', "Check the permissions of the Samba password files.

Procedure:
# ls -lL /etc/samba/passdb.tdb /etc/samba/secrets.tdb

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/samba/passdb.tdb /etc/samba/secrets.tdb'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37109r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22498'
  tag rid: 'SV-37884r1_rule'
  tag stig_id: 'GEN006210'
  tag gtitle: 'GEN006210'
  tag fix_id: 'F-32377r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
