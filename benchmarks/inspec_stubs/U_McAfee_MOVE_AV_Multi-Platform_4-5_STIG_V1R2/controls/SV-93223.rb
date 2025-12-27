control 'SV-93223' do
  title 'All other anti-virus products must be removed from the virtual machine while the McAfee AV Client is running.'
  desc 'Organizations should deploy anti-virus software on all hosts for which satisfactory anti-virus software is available. Anti-virus software should be installed as soon after operating system installation as possible and then updated with the latest anti-virus software patches (to eliminate any known vulnerabilities in the anti-virus software itself). 

To support the security of the host, the anti-virus software should be configured and maintained properly so it continues to be effective at detecting and stopping malware. 

McAfee MOVE AV Client will not function properly with other anti-virus products installed.'
  desc 'check', 'Access the system to which the McAfee MOVE Client is installed. In the taskbar, right-click the red McAfee Agent shield and select "About". 

Ensure neither the "McAfee VirusScan Enterprise + AntiSpyware Enterprise" nor the "Symantec Plugin" is listed as an installed product. 

Access "services.msc" and review the services running on the system. 

Ensure no other antivirus products are installed. 

If either the "McAfee VirusScan Enterprise + AntiSpyware Enterprise" or the "Symantec Plugin" is listed as an installed product in the McAfee Agent "About" dialog box, this is a finding.

If neither the "McAfee VirusScan Enterprise + AntiSpyware Enterprise" nor the "Symantec Plugin" is listed as an installed product, but another antivirus product is shown as running as a service on this system, this is a finding.'
  desc 'fix', 'Click on Start >> Control Panel. Choose "Uninstall a program" under the "Programs" section.

Locate the installed antivirus product, other than the McAfee MOVE AV Client, and choose to uninstall it.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78079r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78517'
  tag rid: 'SV-93223r1_rule'
  tag stig_id: 'MV45-GEN-000001'
  tag gtitle: 'MV45-GEN-000001'
  tag fix_id: 'F-85251r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
