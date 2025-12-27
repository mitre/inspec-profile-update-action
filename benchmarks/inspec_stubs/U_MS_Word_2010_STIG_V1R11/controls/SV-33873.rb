control 'SV-33873' do
  title 'Blocking as default file block opening behavior must be enforced.'
  desc 'Users can open, view, or edit a large number of file types in Word 2010.  Some file types are safer than others, as some could allow malicious code to become active on user computers or the network.  For this reason, disabling or not configuring this setting could allow malicious code to become active on user computers or the network.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security -> Trust Center -> File Block Settings “Set default file block behavior” must be “Enabled: Blocked files are not opened”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\word\\security\\fileblock

Criteria: If the value OpenInProtectedView is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security -> Trust Center -> File Block Settings “Set default file block behavior” to “Enabled: Blocked files are not opened”.'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2010'
  tag check_id: 'C-34252r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26612'
  tag rid: 'SV-33873r1_rule'
  tag stig_id: 'DTOO110 - Word'
  tag gtitle: 'DTOO110 - Set default file block behavior'
  tag fix_id: 'F-29946r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
