control 'SV-31705' do
  title 'All wireless PDA clients used for remote access to DoD networks must have a VPN capability that supports AES encryption.'
  desc 'DoD data could be compromised if transmitted data is not secured with a compliant VPN.'
  desc 'check', 'This check is not applicable if the installed VPN client is not used for remote access to DoD networks. 
Interview the IAO and/or site wireless device administrator and inspect a sample (3-4) of site devices. Review VPN client specification sheets. Verify the VPN client support AES encryption. Mark as a finding if AES is not supported.  Also mark as a finding if no VPN capability is present.'
  desc 'fix', 'Comply with requirement.'
  impact 0.5
  ref 'DPMS Target PDA/PED'
  tag check_id: 'C-25507r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19897'
  tag rid: 'SV-31705r1_rule'
  tag stig_id: 'WIR-MOS-PDA-034-02'
  tag gtitle: 'Remote access VPN - AES encryption'
  tag fix_id: 'F-20573r6_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECWN-1'
end
