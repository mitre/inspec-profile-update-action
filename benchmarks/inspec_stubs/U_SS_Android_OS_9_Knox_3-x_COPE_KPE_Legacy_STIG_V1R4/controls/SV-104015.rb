control 'SV-104015' do
  title 'Samsung Android Workspace must be configured to not enable Microsoft Exchange ActiveSync (EAS) password recovery. This requirement is not applicable if not using Microsoft EAS.'
  desc 'Password Recovery is a feature of Microsoft EAS. Exceeding the Password Attempts limit triggers the Lock screen to open a Password Recovery Mode. 

This feature must be disabled for a Samsung Android device to be in the NIAP-certified Common Criteria (CC) mode of operation.

If Microsoft EAS Password Recovery is enabled, the Samsung device will be out of compliance with the CC Mode configuration. This requirement is configured on the Exchange server. It is the responsibility of the DoD mobile service provider to ensure that the Exchange server has been configured in compliance with the requirement.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify that the Microsoft EAS Password Recovery has been disabled on the Exchange server. 

If on the Microsoft EAS server "password recovery" is not disabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android Workspace to not enable Microsoft EAS Password Recovery. 

The DoD mobile service provider should verify that the Exchange server is configured to disable Microsoft EAS Password Recovery.'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(Legacy)'
  tag check_id: 'C-93247r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93929'
  tag rid: 'SV-104015r1_rule'
  tag stig_id: 'KNOX-09-001365'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-100177r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
