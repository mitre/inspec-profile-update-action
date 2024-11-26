control 'SV-227026' do
  title 'The smb.conf file must use the hosts option to restrict access to Samba.'
  desc 'Samba increases the attack surface of the system and must be restricted to communicate only with systems requiring access.'
  desc 'check', 'Examine the smb.conf file. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

Procedure:
# more /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If the hosts option is not present to restrict access to a list of authorized hosts and networks, this is a finding.'
  desc 'fix', 'Edit the smb.conf file and set the hosts option to permit only authorized hosts to access Samba.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29188r485432_chk'
  tag severity: 'medium'
  tag gid: 'V-227026'
  tag rid: 'SV-227026r603265_rule'
  tag stig_id: 'GEN006220'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29176r485433_fix'
  tag 'documentable'
  tag legacy: ['V-1030', 'SV-40298']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
