control 'SV-55401' do
  title 'The Symantec Endpoint Protection client Insight lookup for threat detection must be enabled.'
  desc 'Antivirus software vendors use collective intelligence from sensors and cross-vector intelligence from web, email, and network threats to compile scores that reflect the likelihood of whether a file in question is malware. The collective intelligence is constantly being updated, more frequently than the typical daily antivirus signature files. With File Reputation lookup, a more real-time response to potential malicious code is realized than with the local-running antivirus software, since querying the cloud-based database when a file appears to be suspicious provides up-to-the-minute intelligence. This type of protection reduces the threat protection time period from days to milliseconds, increases malware detection rates and reduces downtime and remediation costs associated with malware attacks. Using File Reputation lookup is mandated by US CYBERCOM on DoD systems.'
  desc 'check', 'Note: This check is Not Applicable for SIPRNet or higher networks.

GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to the open Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> under the Global Settings tab, Scan Options -> Ensure "Enable Insight for:" is selected. 

Criteria:  If "Enable Insight for:" is not selected, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to the open Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> under the Global Settings tab, Scan Options -> Select "Enable Insight for:".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48944r3_chk'
  tag severity: 'medium'
  tag gid: 'V-42673'
  tag rid: 'SV-55401r2_rule'
  tag stig_id: 'DTASEP009'
  tag gtitle: 'DTASEP009'
  tag fix_id: 'F-48258r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
