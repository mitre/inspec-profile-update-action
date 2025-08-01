control 'SV-110753' do
  title 'All Samsung Android 8 installations must be removed.'
  desc 'Samsung Android 8 is no longer supported by Google and Samsung and therefore, may contain security vulnerabilities.'
  desc 'check', 'Verify there are no installations of Samsung Android 8 at the site.
If Samsung Android 8 is still being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Samsung Android 8.'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-100535r1_chk'
  tag severity: 'high'
  tag gid: 'V-101649'
  tag rid: 'SV-110753r1_rule'
  tag stig_id: 'KNOX-08-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-107333r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
