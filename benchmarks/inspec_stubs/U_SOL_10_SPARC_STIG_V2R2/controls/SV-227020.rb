control 'SV-227020' do
  title 'The smb.conf file must have mode 0644 or less permissive.'
  desc 'If the smb.conf file has excessive permissions, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the mode of the smb.conf file. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

Procedure:
# ls -lL /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf


If the smb.conf has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the smb.conf file to 0644 or less permissive.

Procedure:
# chmod 0644 /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29182r485414_chk'
  tag severity: 'medium'
  tag gid: 'V-227020'
  tag rid: 'SV-227020r603265_rule'
  tag stig_id: 'GEN006140'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29170r485415_fix'
  tag 'documentable'
  tag legacy: ['V-1028', 'SV-40294']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
