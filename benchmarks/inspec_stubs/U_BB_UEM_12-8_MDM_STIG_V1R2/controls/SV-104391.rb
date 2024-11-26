control 'SV-104391' do
  title 'Only authorized versions of the BlackBerry UEM server must be used.'
  desc 'The BlackBerry UEM 12.8 server is no longer supported by BlackBerry and therefore, may contain security vulnerabilities. The BlackBerry UEM 12.8 server is not authorized within the DoD.

CCI-000366'
  desc 'check', 'Interview ISSO and BlackBerry UEM MDM system administrator.

Verify the site is not using the BlackBerry UEM 12.8 MDM.

If the site is using the BlackBerry UEM 12.8 MDM, this is a finding.'
  desc 'fix', 'Remove all versions of BlackBerry UEM 12.8 MDM.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Manager (UEM) 12.8'
  tag check_id: 'C-93749r1_chk'
  tag severity: 'high'
  tag gid: 'V-94561'
  tag rid: 'SV-104391r1_rule'
  tag stig_id: 'BUEM-12-009990'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-100677r1_fix'
  tag 'documentable'
end
