control 'SV-103857' do
  title 'Any accessory that provides wired networking capabilities to a Samsung Android device must not be connected to a DoD network (for example: DeX Station [LAN port], USB to Ethernet adapter, etc.).'
  desc 'If a Samsung Android device uses an accessory that provides wired networking capabilities, and that accessory is connected to a DoD network, then the Samsung Android device would also be connected to the DoD network. Samsung Android devices most likely have a number of personal apps installed that may include malware or have high-risk behaviors (for example, offloading data from the phone to third-party servers outside the United States). In addition, smartphones do not generally meet security requirements for computer devices to connect directly to DoD networks. 

Note: Samsung DeX mode (with input devices) will not work unless the "USB host mode exception list" is configured (see requirement KNOX-09-000750 for more information).

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', "Review accessories that provide wired networking capabilities to Samsung Android devices at the site and verify that the accessories are not connected to a DoD network. 

If accessories that provide wired networking capabilities to Samsung Android devices are connected to DoD networks, this is a finding. 

Note: Connections to a site's guest network that provides Internet-only access can be used. 

Note: This setting cannot be managed by the MDM administrator and is a User-Based Enforcement (UBE) requirement."
  desc 'fix', 'When using an accessory that provides wired networking capabilities to a Samsung Android device, do not connect the accessory to a DoD network. 

Note: This setting cannot be managed by the MDM administrator and is a UBE requirement.'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(AE)'
  tag check_id: 'C-93089r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93771'
  tag rid: 'SV-103857r1_rule'
  tag stig_id: 'KNOX-09-000360'
  tag gtitle: 'PP-MDF-992000'
  tag fix_id: 'F-100017r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
