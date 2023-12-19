control 'SV-251803' do
  title 'Samsung Android must be enrolled as a COBO device.'
  desc 'The Device is the designated application group for the COBO use case.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are enrolled in a DoD-approved use case.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device. 

On the management tool, verify that the default enrollment is set as "Fully managed".

On the Samsung Android device: 
1. Open Settings >> Biometric and Security >> Other Security Settings >> Device Admin Apps.
2. Verify that the management tool Agent is listed.

If on the management tool the default enrollment is not set as "Fully managed", or the management tool Agent is not listed, this is a finding.'
  desc 'fix', 'Enroll the Samsung Android devices in a DoD-approved use case.

On the management tool, configure the default enrollment as "Fully managed".

Refer to the management tool documentation to determine how to configure the device enrollment.'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COBO'
  tag check_id: 'C-55263r814163_chk'
  tag severity: 'medium'
  tag gid: 'V-251803'
  tag rid: 'SV-251803r814165_rule'
  tag stig_id: 'KNOX-12-110010'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-55217r814164_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
