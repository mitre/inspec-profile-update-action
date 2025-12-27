control 'SV-226900' do
  title 'A separate file system must be used for user home directories (such as /home or equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the /export/home path is a separate file system.

# grep /export/home /etc/vfstab

If no result is returned, /export/home is not on a separate file system and this is a finding.

If ZFS is used for home directories, this is not applicable.'
  desc 'fix', 'Migrate the /export/home path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29062r484987_chk'
  tag severity: 'low'
  tag gid: 'V-226900'
  tag rid: 'SV-226900r603265_rule'
  tag stig_id: 'GEN003620'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29050r484988_fix'
  tag 'documentable'
  tag legacy: ['V-12003', 'SV-28618']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
