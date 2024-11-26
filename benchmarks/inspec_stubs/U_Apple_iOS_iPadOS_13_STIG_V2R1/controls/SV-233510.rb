control 'SV-233510' do
  title 'All Apple iOS/iPadOS 13 installations must be removed.'
  desc 'Apple iOS/iPadOS 13 is no longer supported by Apple and therefore, may contain security vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify there are no installations of Apple iOS/iPadOS 13 at the site.
If Apple iOS/iPadOS 13 is being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Apple iOS/iPadOS 13.'
  impact 0.7
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-33406r606410_chk'
  tag severity: 'high'
  tag gid: 'V-233510'
  tag rid: 'SV-233510r606412_rule'
  tag stig_id: 'AIOS-13-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33382r606411_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
