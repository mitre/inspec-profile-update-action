control 'SV-46135' do
  title 'The /etc/smbpasswd file must be owned by root.'
  desc 'If the "smbpasswd" file is not owned by root, it may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check the ownership of the "smbpasswd" file.

# ls -l /etc/samba/passdb.tdb /etc/samba/secrets.tdb

If the "smbpasswd" file is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to configure the files maintained by smbpasswd.
For instance:
# chown root /etc/samba/passdb.tdb /etc/samba/secrets.tdb'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43394r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1029'
  tag rid: 'SV-46135r1_rule'
  tag stig_id: 'GEN006160'
  tag gtitle: 'GEN006160'
  tag fix_id: 'F-39477r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
