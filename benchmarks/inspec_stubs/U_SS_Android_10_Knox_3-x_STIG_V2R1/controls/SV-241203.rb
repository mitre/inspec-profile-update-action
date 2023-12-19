control 'SV-241203' do
  title 'Samsung Android must be configured to disable trust agents. Note: This requirement is not applicable (NA) for specific biometric authentication factors included in the product Common Criteria evaluation.'
  desc 'The fingerprint reader can be used to authenticate the user in order to unlock the mobile device. At this time, no mobile device biometric reader has been evaluated as meeting the security requirements of the MDFPP or been approved for DoD use on mobile devices. This technology could allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #23, FIA_UAU.5.1'
  desc 'check', 'Review Samsung Android configuration settings to determine if Trust Agents are disabled.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device restrictions section, verify that "Trust Agents" are set to "Disable".

On the Samsung Android device, do the following:
1. Open Settings >> Biometrics and security >> Other security settings >> Trust agents.
2. Verify that all listed Trust Agents are disabled and cannot be enabled.

If on the management tool "Trust Agents" are not set to "Disable", or on the Samsung Android device a "Trust Agent" can be enabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable Trust Agents.

On the management tool, in the device restrictions section, set "Trust Agents" to "Disable".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44479r680248_chk'
  tag severity: 'medium'
  tag gid: 'V-241203'
  tag rid: 'SV-241203r680250_rule'
  tag stig_id: 'KNOX-10-002100'
  tag gtitle: 'PP-MDF-301150'
  tag fix_id: 'F-44438r680249_fix'
  tag 'documentable'
  tag legacy: ['SV-109039', 'V-99935']
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
