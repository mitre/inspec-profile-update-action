control 'SV-254527' do
  title 'All Zebra Android 10 installations must be removed.'
  desc 'Zebra Android 10 is no longer supported by Zebra Technologies and therefore, may contain security vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify there are no installations of Zebra Android 10 at the site.

If Zebra Android 10 is being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Zebra Android 10.'
  impact 0.7
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-58011r858438_chk'
  tag severity: 'high'
  tag gid: 'V-254527'
  tag rid: 'SV-254527r866163_rule'
  tag stig_id: 'ZEBR-10-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-57960r858439_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
