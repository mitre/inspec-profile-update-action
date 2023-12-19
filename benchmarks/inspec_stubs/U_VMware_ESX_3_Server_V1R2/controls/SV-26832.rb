control 'SV-26832' do
  title 'Samba must be configured to not allow guest access to shares.'
  desc 'Guest access to shares permits anonymous access and is not permitted.'
  desc 'check', "Check the encryption setting for the Samba configuration. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

Procedure:

# grep -i 'guest ok' /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If the setting exists and is set to yes, this is a finding."
  desc 'fix', 'Edit the /etc/smb.conf file and change the guest ok setting to no.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27815r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22501'
  tag rid: 'SV-26832r2_rule'
  tag stig_id: 'GEN006235'
  tag gtitle: 'GEN006235'
  tag fix_id: 'F-24075r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
