control 'SV-95017' do
  title 'The Samsung DeX Station/Pad multimedia dock must not be connected directly to a DoD network.'
  desc 'If the Samsung DeX Station/Pad multimedia dock is connected to a DoD network, the Samsung smartphone connected to the DeX Station will be connected to the DoD network as well. The Samsung smartphone most likely has a number of personal apps installed that may include malware or have high risk behaviors (for example, offload data from the phone to third-party servers outside the United States). In addition, smartphones do not generally meet security requirements for computer devices to connect directly to DoD networks.

Note: The Samsung DeX Station will not work unless "USB host storage" is enabled (see requirement KNOX-08-015700 for more information).

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', "Review Samsung DeX Station/Pad installations at the site and verify the stations are not connected to DoD networks via wired or wireless connections.

If Samsung DeX Station installations at the site are connected to DoD networks via wired or wireless connections, this is a finding.

Note: Connections to a site's guest wired or wireless network that provides Internet-only access can be used. 

Note: This setting cannot be managed by the MDM Administrator and is a User Based Enforcement (UBE) requirement."
  desc 'fix', 'When using the DeX Station/Pad multimedia dock with a DoD Samsung smartphone, do not connect the DeX Station to a DoD network via a wired or wireless connection. 

Note: This setting cannot be managed by the MDM Administrator and is a UBE requirement.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79985r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80313'
  tag rid: 'SV-95017r1_rule'
  tag stig_id: 'KNOX-08-008200'
  tag gtitle: 'PP-MDF-992000'
  tag fix_id: 'F-87119r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
