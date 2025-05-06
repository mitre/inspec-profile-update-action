control 'SV-37887' do
  title 'The smb.conf file must use the "hosts" option to restrict access to Samba.'
  desc 'Samba increases the attack surface of the system and must be restricted to communicate only with systems requiring access.'
  desc 'check', 'Examine the "smb.conf" file.

# more /etc/samba/smb.conf

If the "hosts" option is not present to restrict access to a list of authorized hosts and networks, this is a finding.'
  desc 'fix', 'Edit the "/etc/samba/smb.conf" file and set the "hosts" option to permit only authorized hosts to access Samba.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37113r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1030'
  tag rid: 'SV-37887r1_rule'
  tag stig_id: 'GEN006220'
  tag gtitle: 'GEN006220'
  tag fix_id: 'F-32381r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
