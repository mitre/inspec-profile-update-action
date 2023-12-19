control 'SV-255137' do
  title 'Samsung Android must be enrolled as a COPE device.'
  desc 'The Work profile is the designated application group for the COPE use case.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are enrolled in a DOD-approved use case.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device. 

On the management tool, verify that the default enrollment is set to "Work profile for company-owned devices".

On the Samsung Android device: 
1. Open Settings >> Security and privacy >> Other security settings >> Device admin apps.
2. Verify that the management tool Agent is listed.
3. Go to the app drawer.
4. Verify that a "Personal" and "Work" tab are present.

If on the management tool the default enrollment is not set as "Work profile for company-owned devices", or on the Samsung Android device the "Personal" and "Work" tabs are not present or the management tool Agent is not listed, this is a finding.'
  desc 'fix', 'Enroll the Samsung Android devices in a DOD-approved use case.

On the management tool, configure the default enrollment as "Work profile for company-owned devices".

Refer to the management tool documentation to determine how to configure the device enrollment.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COPE'
  tag check_id: 'C-58750r867346_chk'
  tag severity: 'medium'
  tag gid: 'V-255137'
  tag rid: 'SV-255137r867348_rule'
  tag stig_id: 'KNOX-13-210010'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58694r867347_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
