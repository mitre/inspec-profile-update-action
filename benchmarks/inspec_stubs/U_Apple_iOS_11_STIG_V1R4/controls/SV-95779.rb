control 'SV-95779' do
  title 'Only authorized versions of the Apple iOS must be used.'
  desc 'Apple iOS 11 is no longer supported by Apple and therefore, may contain security vulnerabilities. Apple iOS 11 is not authorized within the DoD six weeks after the public release of iOS 12.'
  desc 'check', 'Interview ISSO and iOS device system administrator.

Verify the site is not using Apple iOS 11 six weeks after Apple releases iOS 12.  (iOS 12 is expected to be released on or about 15 September 2018.)

If the site is using Apple iOS 11 six weeks after Apple releases iOS 12, this is a finding.'
  desc 'fix', 'Install iOS 12 on all iOS devices.'
  impact 0.7
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-80751r1_chk'
  tag severity: 'high'
  tag gid: 'V-81067'
  tag rid: 'SV-95779r1_rule'
  tag stig_id: 'AIOS-11-015000'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-87869r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
