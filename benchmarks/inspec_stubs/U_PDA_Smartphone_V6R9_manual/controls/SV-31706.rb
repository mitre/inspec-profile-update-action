control 'SV-31706' do
  title 'All wireless PDA clients used for remote access to a DoD network must have a VPN capability that supports CAC authentication.'
  desc 'If an adversary can bypass a VPN’s authentication controls, then the adversary can compromise DoD data transmitted over the VPN and conduct further attacks on DoD networks.  CAC authentication greatly mitigates this risk by providing strong two-factor authentication.'
  desc 'check', 'Interview the IAO and/or site wireless device administrator and inspect a sample (3-4) of site devices.

Verify the VPN client supports CAC authentication to the DoD network (recommend asking the site wireless device administrator to demo this capability).

Mark as a finding if CAC authentication is not supported.'
  desc 'fix', 'Comply with requirement.'
  impact 0.5
  ref 'DPMS Target PDA/PED'
  tag check_id: 'C-25512r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19898'
  tag rid: 'SV-31706r1_rule'
  tag stig_id: 'WIR-MOS-PDA-034-03'
  tag gtitle: 'Remote access VPN - CAC authentication'
  tag fix_id: 'F-20573r6_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECWN-1'
end
