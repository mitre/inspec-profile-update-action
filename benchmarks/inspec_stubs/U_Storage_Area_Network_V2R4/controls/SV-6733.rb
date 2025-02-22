control 'SV-6733' do
  title 'All security related patches are not installed.'
  desc 'Failure to install security related patches leaves the SAN open to attack by exploiting known vulnerabilities.
The IAO/NSO will ensure that all security-related patches are installed.'
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify that all security related patches are installed.'
  desc 'fix', 'After verifying that the patches do not adversely impact the production SAN, create a plan for installing the patches on the SAN, obtain CM approval of the plan, and implement the plan installing the patches.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2454r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6613'
  tag rid: 'SV-6733r1_rule'
  tag stig_id: 'SAN04.003.00'
  tag gtitle: 'All security related patches are not installed.'
  tag fix_id: 'F-6202r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Untested patches can lead to the SAN degradation or failure.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
  tag ia_controls: 'VIVM-1'
end
