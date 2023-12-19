control 'SV-257102' do
  title 'The DOD Mobile Service Provider must not allow BYOADs in facilities where personally owned mobile devices are prohibited.'
  desc 'DOD policy requires BYOAD devices with DOD data be managed by a DOD MDM server, MAM server, or VMI system. This ensures the device can be monitored for compliance with the approved security baseline and managed data and apps can be removed when the device is out of compliance, which protects DOD data from unauthorized exposure. 

Follow local physical security procedures regarding allowing or prohibiting personally owned mobile devices in a DOD facility. If BYOAD devices are brought into facilities where the authorizing official (AO) has determined the risk of using personal devices is unacceptable, this could lead to the exposure of sensitive DOD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the DOD Mobile Service Provider or information system security officer (ISSO)/information system security manager (ISSM) do not allow BYOADs in facilities where personally owned mobile devices are prohibited.

If the DOD Mobile Service Provider or ISSO/ISSM allows BYOADs in facilities where personally owned mobile devices are prohibited, this is a finding.'
  desc 'fix', 'Do not allow BYOADs in facilities where personally owned mobile devices are prohibited.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60787r904049_chk'
  tag severity: 'medium'
  tag gid: 'V-257102'
  tag rid: 'SV-257102r904051_rule'
  tag stig_id: 'AIOS-16-800220'
  tag gtitle: 'PP-BYO-000220'
  tag fix_id: 'F-60728r904050_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
