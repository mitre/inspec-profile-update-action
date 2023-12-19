control 'SV-217835' do
  title 'Samsung Android must be configured to not enable Microsoft Exchange ActiveSync (EAS) password recovery. This requirement is not applicable if not using Microsoft EAS.'
  desc 'Password Recovery is a feature of Microsoft EAS. Exceeding the Password Attempts limit triggers the Lock screen to open a Password Recovery Mode. 

This feature must be disabled for a Samsung Android device to be in the NIAP-certified Common Criteria (CC) mode of operation. 

If Microsoft EAS password recovery is enabled, the Samsung device will be out of compliance with the CC Mode configuration. This requirement is configured on the Exchange server. It is the responsibility of the DoD mobile service provider to ensure the Exchange server has been configured in compliance with the requirement.

The requirement is only applicable if using Microsoft Exchange ActiveSync in the device (personal side).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify that the Microsoft EAS password recovery has been disabled on the Exchange server. 

If on the Microsoft EAS server "password recovery" is not disabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to not enable Microsoft EAS password recovery. 

The DoD mobile service provider should verify that the Exchange server is configured to disable Microsoft EAS password recovery.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE Legacy'
  tag check_id: 'C-19051r362963_chk'
  tag severity: 'medium'
  tag gid: 'V-217835'
  tag rid: 'SV-217835r388482_rule'
  tag stig_id: 'KNOX-09-001375'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-19049r362964_fix'
  tag 'documentable'
  tag legacy: ['SV-104017', 'V-93931']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
