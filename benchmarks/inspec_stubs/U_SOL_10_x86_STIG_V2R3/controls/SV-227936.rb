control 'SV-227936' do
  title 'Samba must be configured to not allow guest access to shares.'
  desc 'Guest access to shares permits anonymous access and is not permitted.'
  desc 'check', "Check the encryption setting for the Samba configuration. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

Procedure:
# grep -i 'guest ok' /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf
If the setting exists and is set to yes, this is a finding."
  desc 'fix', 'Edit the smb.conf file and change the guest ok setting to no.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30098r490228_chk'
  tag severity: 'medium'
  tag gid: 'V-227936'
  tag rid: 'SV-227936r603266_rule'
  tag stig_id: 'GEN006235'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30086r490229_fix'
  tag 'documentable'
  tag legacy: ['V-22501', 'SV-40297']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
