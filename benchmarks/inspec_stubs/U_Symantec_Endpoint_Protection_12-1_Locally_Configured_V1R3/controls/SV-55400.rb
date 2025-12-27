control 'SV-55400' do
  title 'The Symantec Endpoint Protection clients File Reputation Data Submission must be disabled from automatically forwarding selected anonymous security information to Symantec.'
  desc 'Antivirus software vendors use collective intelligence from sensors and cross-vector intelligence from web, email, and network threats to compile scores that reflect the likelihood of whether a file in question is malware. The collective intelligence is constantly being updated, more frequently than the typical daily antivirus signature files. With File Reputation lookup, a more real-time response to potential malicious code is realized than with the local-running antivirus software, since querying the cloud-based database when a file appears to be suspicious provides up-to-the-minute intelligence. This type of protection reduces the threat protection time period from days to milliseconds, increases malware detection rates and reduces downtime and remediation costs associated with malware attacks. Using File Reputation lookup is mandated by US CYBERCOM on DoD systems.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> under Client Management -> Select Configure Settings -> Under the Submissions tab - > Ensure "Let this computer automatically forward selected anonymous security information to Symantec" is not selected. 

Criteria:  If "Let this computer automatically forward selected anonymous security information to Symantec" is selected, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> under Client Management -> Select Configure Settings -> Under the Submissions tab - > Ensure "Let this computer automatically forward selected anonymous security information to Symantec" is not selected.'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48943r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42672'
  tag rid: 'SV-55400r1_rule'
  tag stig_id: 'DTASEP008'
  tag gtitle: 'DTASEP008'
  tag fix_id: 'F-48257r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
