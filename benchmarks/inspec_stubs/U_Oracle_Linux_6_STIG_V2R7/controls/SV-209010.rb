control 'SV-209010' do
  title 'The system must use SMB client signing for connecting to samba servers using smbclient.'
  desc 'Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit.'
  desc 'check', 'To verify that Samba clients running smbclient must use packet signing, run the following command: 

# grep signing /etc/samba/smb.conf

The output should show: 

client signing = mandatory

If it is not, this is a finding.'
  desc 'fix', 'To require samba clients running "smbclient" to use packet signing, add the following to the "[global]" section of the Samba configuration file in "/etc/samba/smb.conf": 

client signing = mandatory

Requiring samba clients such as "smbclient" to use packet signing ensures they can only communicate with servers that support packet signing.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9263r357815_chk'
  tag severity: 'low'
  tag gid: 'V-209010'
  tag rid: 'SV-209010r793731_rule'
  tag stig_id: 'OL6-00-000272'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9263r357816_fix'
  tag 'documentable'
  tag legacy: ['SV-65057', 'V-50851']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
