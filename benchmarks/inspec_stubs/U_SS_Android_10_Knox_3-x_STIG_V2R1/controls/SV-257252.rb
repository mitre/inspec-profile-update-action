control 'SV-257252' do
  title 'All Samsung Android 10 installations must be removed.'
  desc 'Samsung Android 10 is no longer supported by Samsung and therefore may contain security vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify there are no installations of Samsung Android 10 at the site.

If Samsung Android 10 is being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Samsung Android 10.'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-60937r916413_chk'
  tag severity: 'high'
  tag gid: 'V-257252'
  tag rid: 'SV-257252r916415_rule'
  tag stig_id: 'KNOX-10-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-60878r916414_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
