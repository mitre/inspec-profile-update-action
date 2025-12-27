control 'SV-53571' do
  title 'All automatic loading from trusted locations must be disabled.'
  desc "Trusted locations specified in the Trust Center are used to define file locations assumed to be safe. Content, code, and add-ins are allowed to load from trusted locations with a minimal amount of security, without prompting the users for permission. If a dangerous file is opened from a trusted location, it will not be subject to standard security measures and could harm users' computers or data. By default, files located in trusted locations (those specified in the Trust Center) are assumed to be safe."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Security -> Trust Center -> Trusted Locations "Disable all trusted locations" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\word\\security\\trusted locations

Criteria: If the value AllLocationsDisabled is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Security -> Trust Center -> Trusted Locations "Disable all trusted locations" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2013'
  tag check_id: 'C-47720r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17471'
  tag rid: 'SV-53571r1_rule'
  tag stig_id: 'DTOO133'
  tag gtitle: 'DTOO133-Disable all trusted locations'
  tag fix_id: 'F-46495r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
