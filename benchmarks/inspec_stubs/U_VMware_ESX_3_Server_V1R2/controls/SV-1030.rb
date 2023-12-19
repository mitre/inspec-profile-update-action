control 'SV-1030' do
  title 'The smb.conf file must use the hosts option to restrict access to Samba.'
  desc 'Samba increases the attack surface of the system and must be restricted to communicate only with systems requiring access.'
  desc 'check', 'Examine the smb.conf file. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

# more /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If the hosts option is not present to restrict access to a list of authorized hosts and networks, this is a finding.'
  desc 'fix', 'Edit the smb.conf file and set the hosts option to permit only authorized hosts to access Samba.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2052r4_chk'
  tag severity: 'medium'
  tag gid: 'V-1030'
  tag rid: 'SV-1030r3_rule'
  tag stig_id: 'GEN006220'
  tag gtitle: 'GEN006220'
  tag fix_id: 'F-1184r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
