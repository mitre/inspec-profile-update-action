control 'SV-109107' do
  title 'All Samsung Android 7 installations must be removed.'
  desc 'Samsung Android 7 is no longer supported by Google and Samsung and therefore, may contain security vulnerabilities.'
  desc 'check', 'Verify there are no installations of Samsung Android 7 at the site.
If Samsung Android 7 is still being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Samsung Android 7.'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-98853r1_chk'
  tag severity: 'high'
  tag gid: 'V-100003'
  tag rid: 'SV-109107r1_rule'
  tag stig_id: 'KNOX-07-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-105687r1_fix'
  tag 'documentable'
end
