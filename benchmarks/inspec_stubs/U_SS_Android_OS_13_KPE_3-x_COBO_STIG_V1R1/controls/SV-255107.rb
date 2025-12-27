control 'SV-255107' do
  title 'Samsung Android must be enrolled as a COBO device.'
  desc 'The device is the designated application group for the COBO use case.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are enrolled in a DOD-approved use case.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device. 

On the management tool, verify that the default enrollment is set as "Fully managed".

On the Samsung Android device: 
1. Open Settings >> Security and privacy >> Other security settings >> Device admin apps.
2. Verify that the management tool Agent is listed.

If on the management tool the default enrollment is not set as "Fully managed", or the management tool Agent is not listed, this is a finding.'
  desc 'fix', 'Enroll the Samsung Android devices in a DOD-approved use case.

On the management tool, configure the default enrollment as "Fully managed".

Refer to the management tool documentation to determine how to configure the device enrollment.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COBO'
  tag check_id: 'C-58720r867256_chk'
  tag severity: 'medium'
  tag gid: 'V-255107'
  tag rid: 'SV-255107r867258_rule'
  tag stig_id: 'KNOX-13-110010'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58664r867257_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
