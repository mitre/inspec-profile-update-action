control 'SV-108673' do
  title 'The Jamf Pro EMM server must configure the MDM Agent/platform to enable the DoD required device enrollment restrictions allowed for enrollment [specific device model].'
  desc 'Good configuration management of a mobile device is a key capability for maintaining the mobile device’s security baseline. Restricting network access to only authorized devices is a key configuration management attribute. Device type is a key way to specify mobile devices that can be adequately secured.

SFR ID: FMT_SMF.1.1(2) b, FIA_ENR_EXT.1.2'
  desc 'check', 'Verify device enrollment restrictions are set up to limit enrollment by iOS device.

1. Open Jamf Pro admin interface.
2. Select "Devices".
3. Select "Smart Device Groups".
4. Select desired device group.
5. Verify approved model numbers are listed.

If device enrollment restrictions are not set up, this is a finding.'
  desc 'fix', 'Build Smart Device Group that matches DoD requirements and said groups are within exclusions of Configuration Profiles, Mobile Device Apps, etc.

1. Open Jamf Pro admin interface.
2. Select "Devices".
3. Select "Smart Device Groups".
4. Select "New".
5. Enter a name for the group.
6. Select "Criteria".
7. Select "Add" to add new Model, Model Identifier, or Model Number.
8. Continue to add all models that satisfy this requirement.
9. Select "Save".

Add this Smart Device Group to any Configuration Profile, Mobile Device Apps as an Exception Scope.'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98419r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99569'
  tag rid: 'SV-108673r1_rule'
  tag stig_id: 'JAMF-10-000440'
  tag gtitle: 'PP-MDM-411046'
  tag fix_id: 'F-105253r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
