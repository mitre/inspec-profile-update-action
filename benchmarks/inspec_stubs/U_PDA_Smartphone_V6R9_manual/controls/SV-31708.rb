control 'SV-31708' do
  title 'Wireless PDA VPNs must operate with split tunneling disabled.'
  desc 'DoD data could be compromised if transmitted data is not secured with a compliant VPN.'
  desc 'check', 'This check is not applicable if the installed VPN client is not used for remote access to DoD networks.
Interview the IAO and/or site wireless device administrator and inspect a sample (3-4) of site devices. Check to see if the VPN has a setting to disable split tunneling. The following test can also be done: 
1. Connect to the Internet using the PDA browser. 
2. Launch the VPN client and connect to the DoD network. 
3. Check to see if the browser is still connected to the Internet. If yes, split tunneling is not disabled.

Mark as a finding if split tunneling is not disabled on all PDA VPN clients as the default configuration setting.'
  desc 'fix', 'Comply with requirement.'
  impact 0.5
  ref 'DPMS Target PDA/PED'
  tag check_id: 'C-25520r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19899'
  tag rid: 'SV-31708r1_rule'
  tag stig_id: 'WIR-MOS-PDA-034-04'
  tag gtitle: 'Remote access VPN - split tunneling'
  tag fix_id: 'F-20573r6_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECWN-1'
end
