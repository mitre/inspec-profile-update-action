control 'SV-55406' do
  title 'The Symantec Endpoint Protection client Auto-Protect Advanced Options must be configured to scan files when accessed or modified.'
  desc "Interpreted viruses are executed by an application. Within this subcategory, macro viruses take advantage of the capabilities of applications' macro programming language to infect application documents and document templates, while scripting viruses infect scripts that are understood by scripting languages processed by services on the OS. Many attackers use toolkits containing several different types of utilities and scripts that can be used to probe and attack hosts. (NIST SP 800-83) The scanning of files when accessed or modified is crucial in preventing these attacks."
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Advanced -> Under Scan files when -> Ensure "Scan when a file is accessed or modified" is selected. 

Criteria:  If "Scan when a file is accessed or modified" is not selected, this is a finding. 

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of Reads is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Advanced -> Under Scan files when -> Select "Scan when a file is accessed or modified".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48949r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42678'
  tag rid: 'SV-55406r1_rule'
  tag stig_id: 'DTASEP014'
  tag gtitle: 'DTASEP014'
  tag fix_id: 'F-48263r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
