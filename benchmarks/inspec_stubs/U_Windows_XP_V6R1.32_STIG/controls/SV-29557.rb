control 'SV-29557' do
  title 'The HBSS McAfee Agent is not installed.'
  desc 'check', 'Search for the file FrameworkService.exe (by default in the \\Program Files\\McAfee\\Common Framework\\ directory) and check that the version is 4 or above.

AND verify that the Service "McAfee Framework Service" is running.

If either of these conditions does not exist, then this is a finding.'
  desc 'fix', 'Deploy the McAfee Agent as detailed in the CTO and in accordance with the DoD HBSS STIG.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-34533r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15505'
  tag rid: 'SV-29557r1_rule'
  tag gtitle: 'HBSS McAfee Agent'
  tag fix_id: 'F-30040r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
