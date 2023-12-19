control 'SV-6809' do
  title 'Fabric switch configurations and management station configuration are not archived and/or copies of the operating system and other critical software for all SAN components are not stored in a fire rated container or are not collocated with the operational software.'
  desc '.Backup and recovery procedures are critical to the security and availability of the SAN system.  If a system is compromised, shut down, or otherwise not available for service, this could hinder the availability of resources to the warfighter.
The IAO/NSO will ensure that all fabric switch configurations and management station configuration are archived and copies of the operating system and other critical software for all SAN components are stored in a fire rated container or otherwise not collocated with the operational software.'
  desc 'check', 'The reviewer will interview the IAO/NSO and view the stored information to verify that all fabric switch configurations and management station configuration are archived and copies of the operating system and other critical software for all SAN components are stored in a fire rated container or otherwise not collocated with the operational software.'
  desc 'fix', 'Develop a plan that will ensure that all fabric switch configurations and management station configuration are archived and copies of the operating system and other critical software for all SAN components are stored in a fire rated container or otherwise not collocated with the operational software.  Obtain CM approval for the plan and implement the plan.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2589r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6661'
  tag rid: 'SV-6809r1_rule'
  tag stig_id: 'SAN05.001.00'
  tag gtitle: 'Backup of critical SAN Software and configurations'
  tag fix_id: 'F-6256r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
  tag ia_controls: 'COSW-1'
end
