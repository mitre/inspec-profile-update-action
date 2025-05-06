control 'SV-255300' do
  title 'All Google Android 10 installations must be removed.'
  desc 'Google Android 10 is no longer supported by Google and therefore, may contain security vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify there are no installations of Google Android 10 at the site.
If Google Android 10 is being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Google Android 10.'
  impact 0.7
  ref 'DPMS Target Google Android 10-x'
  tag check_id: 'C-58973r873675_chk'
  tag severity: 'high'
  tag gid: 'V-255300'
  tag rid: 'SV-255300r875513_rule'
  tag stig_id: 'GOOG-10-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-58917r873676_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
