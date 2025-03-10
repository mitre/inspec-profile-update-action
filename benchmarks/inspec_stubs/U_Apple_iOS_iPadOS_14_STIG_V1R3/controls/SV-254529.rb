control 'SV-254529' do
  title 'All Apple iOS/iPadOS 14 installations must be removed.'
  desc 'Apple iOS/iPadOS 14 is no longer supported by Apple and therefore, may contain security vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify there are no installations of Apple iOS/iPadOS 14 at the site.

If Apple iOS/iPadOS 14 is being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Apple iOS/iPadOS 14.'
  impact 0.7
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-58013r858444_chk'
  tag severity: 'high'
  tag gid: 'V-254529'
  tag rid: 'SV-254529r859304_rule'
  tag stig_id: 'AIOS-14-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-57962r858445_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
