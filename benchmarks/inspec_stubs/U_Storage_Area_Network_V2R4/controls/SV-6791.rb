control 'SV-6791' do
  title 'All SAN management consoles and ports are not password protected.'
  desc 'Without password protection malicious users can create a denial of service by disrupting the SAN or allow the compromise of sensitive date by reconfiguring the SAN topography.
The IAO/NSO will ensure that all SAN management consoles and ports are password protected.'
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify that all SAN management consoles and ports are password protected.'
  desc 'fix', 'Develop a plan for implementing password protection on the SAN’s management consoles and ports.  Obtain CM approval of the plan and execute the plan.'
  impact 0.7
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2571r1_chk'
  tag severity: 'high'
  tag gid: 'V-6645'
  tag rid: 'SV-6791r1_rule'
  tag stig_id: 'SAN04.017.00'
  tag gtitle: 'Password SAN Management Console and Ports'
  tag fix_id: 'F-6248r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end
