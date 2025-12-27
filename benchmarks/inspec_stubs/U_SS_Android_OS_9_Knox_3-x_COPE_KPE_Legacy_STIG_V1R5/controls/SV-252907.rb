control 'SV-252907' do
  title 'All Samsung Android 9 installations must be removed.'
  desc 'Samsung Android 9 is no longer supported by Samsung and therefore may contain security vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify there are no installations of Samsung Android 9 at the site.

If Samsung Android 09 is being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Samsung Android 9.'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE Legacy'
  tag check_id: 'C-56360r835031_chk'
  tag severity: 'high'
  tag gid: 'V-252907'
  tag rid: 'SV-252907r835032_rule'
  tag stig_id: 'KNOX-09-999994'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-56310r835027_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
