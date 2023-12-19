control 'SV-257095' do
  title "The iOS/iPadOS 16 BYOAD must be configured to protect users' privacy, personal information, and applications."
  desc 'A key construct of a BYOAD is that user personal information and data are protected from exposure to the enterprise. 

Reference: DOD policy "Use of Non-Government Mobile Devices". 3.b.(4), 3.b.(5).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', "Verify the EMM system has been configured to limit access to unmanaged data and apps on the iOS/iPadOS 16 BYOAD to protect users' privacy, personal information, and applications. 

The exact procedure will depend on the EMM system used at the site.

If the BYOAD has not been configured to limit access to unmanaged data and apps on the iOS/iPadOS 16 BYOAD, this is a finding."
  desc 'fix', "Configure the EMM system to limit access to unmanaged data and apps on the iOS/iPadOS 16 BYOAD to protect users' privacy, personal information, and applications. 

The exact procedure will depend on the EMM system used at the site."
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60780r904028_chk'
  tag severity: 'low'
  tag gid: 'V-257095'
  tag rid: 'SV-257095r904030_rule'
  tag stig_id: 'AIOS-16-800120'
  tag gtitle: 'PP-BYO-000120'
  tag fix_id: 'F-60721r904029_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
