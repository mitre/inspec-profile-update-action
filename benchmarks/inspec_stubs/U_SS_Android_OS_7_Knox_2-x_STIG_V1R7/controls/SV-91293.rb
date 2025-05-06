control 'SV-91293' do
  title 'The Samsung DeX Station multimedia dock must not be connected directly to a DoD network.'
  desc 'If the Samsung DeX Station multimedia dock is connected to a DoD network, the Samsung smartphone connected to the DeX Station will be connected to the DoD network as well. The Samsung smartphone most likely has a number of personal apps installed that may include malware or have high risk behaviors (for example, off load data from the phone to third-party servers outside the United States). In addition, Smartphones do not generally meet security requirements for computer devices to connect directly to DD networks.

Note: The Samsung DeX Station will not work unless "USB host storage" is enabled (see requirement KNOX-07-012600 for more information).

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', "Review Samsung DeX Station installations at the site and verify the stations are not connected to DoD networks via wired or wireless connections.

If Samsung DeX Station installations at the site are connected to DoD networks via wired or wireless connections, this is a finding.

Note: Connections to a site's guest wired or wireless network that provides Internet-only access can be used.

Note: This setting cannot be managed by the MDM administrator and is a User Based Enforcement (UBE) requirement."
  desc 'fix', 'When using the DeX Station multimedia dock with a DoD Samsung smartphone, do not connect the DeX Station to a DoD network via a wired or wireless connection.

Note: This setting cannot be managed by the MDM administrator and is a User Based Enforcement (UBE) requirement.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76265r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76597'
  tag rid: 'SV-91293r1_rule'
  tag stig_id: 'KNOX-07-017000'
  tag gtitle: 'PP-MDF-992000'
  tag fix_id: 'F-83291r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
