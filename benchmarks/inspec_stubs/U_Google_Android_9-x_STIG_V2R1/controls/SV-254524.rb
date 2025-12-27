control 'SV-254524' do
  title 'All Google Android 9 installations must be removed.'
  desc 'Google Android 9 is no longer supported by Apple and therefore, may contain security vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify there are no installations of Google Android 9 at the site.

If Google Android 9 is being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Google Android 9.'
  impact 0.7
  ref 'DPMS Target Google Android 9-x'
  tag check_id: 'C-58008r858429_chk'
  tag severity: 'high'
  tag gid: 'V-254524'
  tag rid: 'SV-254524r858431_rule'
  tag stig_id: 'GOOG-09-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-57957r858430_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
