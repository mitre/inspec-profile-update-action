control 'SV-257086' do
  title 'The EMM system supporting the iOS/iPadOS 16 BYOAD must be configured to initiate autonomous monitoring, compliance, and validation prior to granting the BYOAD access to DOD information and IT resources.'
  desc 'DOD policy requires BYOAD devices with DOD data be managed by a DOD MDM server, MAM server, or VMI system. This ensures the device can be monitored for compliance with the approved security baseline and managed data and apps can be removed when the device is out of compliance, which protects DOD data from unauthorized exposure.

Reference: DOD policy "Use of Non-Government Mobile Devices". 3.a.(3)iii.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM system supporting the iOS/iPadOS 16 BYOAD has been configured to initiate autonomous monitoring, compliance, and validation prior to granting the BYOAD access to DOD information and IT resources. The exact procedure will depend on the EMM system used at the site.

If the EMM system supporting the iOS/iPadOS 16 BYOAD has not been configured to initiate autonomous monitoring, compliance, and validation prior to granting the BYOAD access to DOD information and IT resources, this is a finding.'
  desc 'fix', 'Configure the EMM system supporting the iOS/iPadOS 16 BYOAD to initiate autonomous monitoring, compliance, and validation prior to granting the BYOAD access to DOD information and IT resources. The exact procedure will depend on the EMM system used at the site.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60771r904001_chk'
  tag severity: 'medium'
  tag gid: 'V-257086'
  tag rid: 'SV-257086r904003_rule'
  tag stig_id: 'AIOS-16-800030'
  tag gtitle: 'PP-BYO-000030'
  tag fix_id: 'F-60712r904002_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
