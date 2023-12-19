control 'SV-254577' do
  title 'All Motorola Android 9 installations must be removed.'
  desc 'Motorola Android 9 is no longer supported by Motorola and therefore, may contain security vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify there are no installations of Motorola Android 9 at the site.

If Motorola Android 9 is being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Motorola Android 9.'
  impact 0.7
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-58188r859999_chk'
  tag severity: 'high'
  tag gid: 'V-254577'
  tag rid: 'SV-254577r865213_rule'
  tag stig_id: 'MOTO-09-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-58134r860000_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
