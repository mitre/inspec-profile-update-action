control 'SV-255499' do
  title 'All Google Android 11 installations must be removed.'
  desc 'Google Android 11 is no longer supported by Google and therefore, may contain security vulnerabilities.
SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify there are no installations of Google Android 11 at the site.
If Google Android 11 is being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Google Android 11.'
  impact 0.7
  ref 'DPMS Target Google Android 11 COPE'
  tag check_id: 'C-59171r873679_chk'
  tag severity: 'high'
  tag gid: 'V-255499'
  tag rid: 'SV-255499r873683_rule'
  tag stig_id: 'GOOG-011-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-59115r873680_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
