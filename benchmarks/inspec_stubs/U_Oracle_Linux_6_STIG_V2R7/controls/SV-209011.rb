control 'SV-209011' do
  title 'The system must use SMB client signing for connecting to samba servers using mount.cifs.'
  desc 'Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit.'
  desc 'check', 'If Samba is not in use, this is not applicable.

To verify that Samba clients using mount.cifs must use packet signing, run the following command: 

# grep sec /etc/fstab /etc/mtab

The output should show either "krb5i" or "ntlmv2i" in use. 
If it does not, this is a finding.'
  desc 'fix', 'Require packet signing of clients who mount Samba shares using the "mount.cifs" program (e.g., those who specify shares in "/etc/fstab"). To do so, ensure signing options (either "sec=krb5i" or "sec=ntlmv2i") are used. 

See the "mount.cifs(8)" man page for more information. A Samba client should only communicate with servers who can support SMB packet signing.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9264r357818_chk'
  tag severity: 'low'
  tag gid: 'V-209011'
  tag rid: 'SV-209011r793732_rule'
  tag stig_id: 'OL6-00-000273'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9264r357819_fix'
  tag 'documentable'
  tag legacy: ['SV-65059', 'V-50853']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
