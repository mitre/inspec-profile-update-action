control 'SV-254521' do
  title 'All Apple iOS 12 installations must be removed.'
  desc 'Apple iOS 12 is no longer supported by Apple and therefore, may contain security vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify there are no installations of Apple iOS 12 at the site.

If Apple iOS 12 is being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Apple iOS 12.'
  impact 0.7
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-58005r858422_chk'
  tag severity: 'high'
  tag gid: 'V-254521'
  tag rid: 'SV-254521r858424_rule'
  tag stig_id: 'AIOS-12-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-57954r858423_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
