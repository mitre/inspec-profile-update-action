control 'SV-218647' do
  title 'The smb.conf file must use the hosts option to restrict access to Samba.'
  desc 'Samba increases the attack surface of the system and must be restricted to communicate only with systems requiring access.'
  desc 'check', 'Examine the "smb.conf" file.

# more /etc/samba/smb.conf

If the "hosts" option is not present to restrict access to a list of authorized hosts and networks, this is a finding.'
  desc 'fix', 'Edit the "/etc/samba/smb.conf" file and set the "hosts" option to permit only authorized hosts to access Samba.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20122r556139_chk'
  tag severity: 'medium'
  tag gid: 'V-218647'
  tag rid: 'SV-218647r603259_rule'
  tag stig_id: 'GEN006220'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20120r556140_fix'
  tag 'documentable'
  tag legacy: ['V-1030', 'SV-64055']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
