control 'SV-55393' do
  title 'The Symantec Endpoint Protection clients antivirus signature file age must be no older than 7 days.'
  desc 'Antivirus signature files are updated almost daily by antivirus software vendors. These files are made available to antivirus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. Without current virus definitions the virus scan will not be able to detect new viruses, putting the system and network at risk.'
  desc 'check', 'Note:  If the vendor or trusted site’s files are also older than 7 days and match the date of the signature files on the machine, this is not a finding.          

On the machine, locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. Under the Status tab, observe the "Definitions:" area for Virus and Spyware Protection, Proactive Threat Protection, and Network Threat Protection.                                                                                                                                              

Criteria:  If the "Definitions:" date is older than 7 calendar days from the current date, this is a finding. 

On the machine use the Windows Registry Editor to navigate to the following key:
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\CurrentVersion\\public-opstate
64 bit:  
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\CurrentVersion\\public-opstate        

Criteria:  If the "LatestVirusDefsDate" is older than 7 calendar days from the current date, this is a finding.

Note:  If the vendor or trusted site’s files are also older than 7 days and match the date of the signature files on the machine, this is not a finding.'
  desc 'fix', 'Update client machines via the Symantec Enterprise Console. If this fails to update the client, update the antivirus signature files as local process describes (e.g., auto update or LiveUpdate).'
  impact 0.7
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48935r1_chk'
  tag severity: 'high'
  tag gid: 'V-42665'
  tag rid: 'SV-55393r1_rule'
  tag stig_id: 'DTASEP001'
  tag gtitle: 'DTASEP001'
  tag fix_id: 'F-48249r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
