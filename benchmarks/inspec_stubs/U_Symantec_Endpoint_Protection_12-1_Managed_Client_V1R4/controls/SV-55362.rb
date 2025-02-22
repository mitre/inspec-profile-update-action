control 'SV-55362' do
  title 'The Symantec Endpoint Protection client Auto-Protect Advanced Options must be configured to scan files when accessed or modified.'
  desc "Interpreted viruses are executed by an application. Within this subcategory, macro viruses take advantage of the capabilities of applications' macro programming language to infect application documents and document templates, while scripting viruses infect scripts that are understood by scripting languages processed by services on the OS. Many attackers use toolkits containing several different types of utilities and scripts that can be used to probe and attack hosts. (NIST SP 800-83) The scanning of files when accessed or modified is crucial in preventing these attacks."
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Scan Details tab -> Under Scanning, Additional Options -> Select Advanced Scanning and Monitoring -> Under Scan Files When -> Ensure "Scan when a file is accessed or modified" is selected. 

Criteria:  If "Scan when a file is accessed or modified" is not selected, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of Reads is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology, select Auto-Protect -> Select the Scan Details tab -> Under Scanning, Additional Options -> Select Advanced Scanning and Monitoring -> Under Scan Files When -> Select "Scan when a file is accessed or modified" .'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48905r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42634'
  tag rid: 'SV-55362r1_rule'
  tag stig_id: 'DTASEP014'
  tag gtitle: 'DTASEP014'
  tag fix_id: 'F-48218r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
