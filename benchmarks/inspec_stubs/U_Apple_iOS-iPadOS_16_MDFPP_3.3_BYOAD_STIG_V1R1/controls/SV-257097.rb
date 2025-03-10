control 'SV-257097' do
  title 'The iOS/iPadOS 16 BYOAD must be deployed in Device Enrollment mode or User Enrollment mode.'
  desc 'DOD policy requires BYOAD devices with DOD data be managed by a DOD MDM server, MAM server, or VMI system. This ensures the device can be monitored for compliance with the approved security baseline and the work profile can be removed when the device is out of compliance, which protects DOD data from unauthorized exposure.

Note: Technical limitations prohibit using Apple iOS/iPadOS User Enrollment in most DOD environments.

Reference: DOD policy "Use of Non-Government Mobile Devices". 

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify iOS/iPadOS 16 BYOAD has been deployed in Device Enrollment mode or User Enrollment mode.

This procedure is performed on the iPhone and iPad. 

For Device Enrollment:
1. On the device, go to Settings >> General >> VPN & Device Management. 
2. Verify a Mobile Device Management profile is installed on the device.

For User Enrollment: 
1. On the device, go to Settings >> General >> VPN & Device Management. 
2. Verify a Mobile Device Management profile is installed on the device.
3. On the device, go to "Settings" and click on the User icon. 
4. Verify a work AppleID is listed.

If the iOS/iPadOS 16 BYOAD has not been deployed in Device Enrollment mode or User Enrollment mode, this is a finding.'
  desc 'fix', 'Deploy iOS/iPadOS 16 BYOAD in Device Enrollment mode or User Enrollment mode. 

The exact procedure will depend on the EMM system used at the site.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60782r904034_chk'
  tag severity: 'medium'
  tag gid: 'V-257097'
  tag rid: 'SV-257097r904036_rule'
  tag stig_id: 'AIOS-16-800150'
  tag gtitle: 'PP-BYO-000150'
  tag fix_id: 'F-60723r904035_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
