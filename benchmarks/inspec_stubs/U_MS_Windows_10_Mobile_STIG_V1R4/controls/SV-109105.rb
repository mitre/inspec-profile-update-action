control 'SV-109105' do
  title 'All Windows 10 Mobile installations must be removed.'
  desc 'Windows 10 Mobile is no longer supported by Microsoft and therefore, may contain security vulnerabilities.'
  desc 'check', 'Verify there are no installations of Windows 10 Mobile at the site.

If Windows 10 Mobile is still being used at the site, this is a finding.'
  desc 'fix', 'Remove all installations of Windows 10 Mobile.'
  impact 0.7
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-98851r1_chk'
  tag severity: 'high'
  tag gid: 'V-100001'
  tag rid: 'SV-109105r1_rule'
  tag stig_id: 'MSWM-10-999999'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-105685r1_fix'
  tag 'documentable'
end
