control 'SV-53468' do
  title 'Blocking as default file block opening behavior must be enforced.'
  desc 'Users can open, view, or edit a large number of file types in PowerPoint 2013.  Some file types are safer than others, as some could allow malicious code to become active on user computers or the network.  For this reason, disabling or not configuring this setting could allow malicious code to become active on user computers or the network.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2013 -> PowerPoint Options -> Security -> Trust Center -> File Block Settings "Set default file block behavior" is set to "Enabled: Blocked files are not opened".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\PowerPoint\\security\\fileblock

Criteria: If the value OpenInProtectedView is REG_DWORD = 0, this is not a finding'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2013 -> PowerPoint Options -> Security -> Trust Center -> File Block Settings "Set default file block behavior" to "Enabled: Blocked files are not opened".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2013'
  tag check_id: 'C-47669r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26612'
  tag rid: 'SV-53468r1_rule'
  tag stig_id: 'DTOO110'
  tag gtitle: 'DTOO110 - Set default file block behavior'
  tag fix_id: 'F-46393r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
