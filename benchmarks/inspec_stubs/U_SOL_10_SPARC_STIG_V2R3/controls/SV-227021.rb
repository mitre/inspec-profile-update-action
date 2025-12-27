control 'SV-227021' do
  title 'The smb.conf file must not have an extended ACL.'
  desc 'Excessive permissions could endanger the security of the Samba configuration file and, ultimately, the system and network.'
  desc 'check', 'Check the group ownership of the Samba configuration file. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

Procedure:
# ls -lL /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29183r485417_chk'
  tag severity: 'medium'
  tag gid: 'V-227021'
  tag rid: 'SV-227021r603265_rule'
  tag stig_id: 'GEN006150'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29171r485418_fix'
  tag 'documentable'
  tag legacy: ['SV-26824', 'V-22497']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
