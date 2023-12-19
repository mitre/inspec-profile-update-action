control 'SV-85629' do
  title 'All automatic loading from trusted locations must be disabled.'
  desc "This policy setting allows administrators to disable all trusted locations in the specified applications. Trusted locations specified in the Trust Center are used to define file locations that are assumed to be safe. Content, code, and add-ins are allowed to load from trusted locations with a minimal amount of security, without prompting the users for permission. If a dangerous file is opened from a trusted location, it will not be subject to standard security measures and could harm users' computers or data. If you enable this policy setting, all trusted locations (those specified in the Trust Center) in the specified applications are ignored, including any trusted locations established by Office 2016 during setup, deployed to users using Group Policy, or added by users themselves.  Users will be prompted again when opening files from trusted locations. If you disable or do not configure this policy setting, all trusted locations (those specified in the Trust Center) in the specified applications are assumed to be safe."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> Trust Center -> Trusted Locations "Disable all trusted locations" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\excel\\security\\trusted locations

Criteria: If the value AllLocationsDisabled is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> Trust Center -> Trusted Locations "Disable all trusted locations" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2016'
  tag check_id: 'C-71433r2_chk'
  tag severity: 'medium'
  tag gid: 'V-71005'
  tag rid: 'SV-85629r1_rule'
  tag stig_id: 'DTOO133'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-77337r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
