control 'SV-53724' do
  title 'Disallowance of trusted locations on the network must be enforced.'
  desc %q(Files located in trusted locations and specified in the Trust Center are typically assumed to be safe. Content, code, and add-ins are allowed to load from trusted locations with minimal security and without prompting the user for permission. By default, users can specify "Trusted Locations" on network shares, or in other remote locations not under their direct control, by selecting the "Allow Trusted Locations on my network" (not recommended) check box in the "Trusted Locations" section of the Trust Center. If a dangerous file is opened from a trusted location, it will not be subject to typical security measures and could affect users' computers or data.)
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center -> Trusted Locations "Allow Trusted Locations on the network" is set to Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\excel\\security\\trusted locations

Criteria: If the value AllowNetworkLocations is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center -> Trusted Locations "Allow Trusted Locations on the network" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47810r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17520'
  tag rid: 'SV-53724r1_rule'
  tag stig_id: 'DTOO134'
  tag gtitle: 'DTOO134 - Trusted locations on computer'
  tag fix_id: 'F-46633r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
