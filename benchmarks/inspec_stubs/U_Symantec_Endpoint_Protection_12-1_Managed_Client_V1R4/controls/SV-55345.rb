control 'SV-55345' do
  title 'The Symantec Endpoint Protection client Insight Lookup for threat detection must be enabled.'
  desc 'Antivirus software vendors use collective intelligence from sensors and cross-vector intelligence from web, email and network threats to compile scores that reflect the likelihood of whether a file in question is malware. The collective intelligence is constantly being updated, more frequently than the typical daily antivirus signature files. With File Reputation lookup, a more real-time response to potential malicious code is realized than with the local-running antivirus software, since querying the cloud-based database when a file appears to be suspicious provides up- to- the minute intelligence. This type of protection reduces the threat protection time period from days to milliseconds, increases malware detection rates and reduces downtime and remediation costs associated with malware attacks. Using File Reputation lookup is mandated by US CYBERCOM on DoD systems.'
  desc 'check', 'Note: This check is Not Applicable for SIPRnet or higher networks.

Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans, select Administrator-Defined Scans -> Select the applied scan and click Edit -> Select the Insight Lookup tab -> Ensure "Enable Insight for:" is selected. 

Criteria:  If "Enable Insight for:" is not selected, this is a finding.

Client check:  Locate the Symantec Endpoint Protection icon in the system tray.  Double-click the icon to the open Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Global Settings tab, Scan Options -> Ensure "Enable Insight for:" is selected. 

Criteria:  If "Enable Insight for:" is not selected, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans select Administrator-Defined Scans -> Select the applied scan and click Edit -> Select the Insight Lookup tab -> Select "Enable Insight for:".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48898r5_chk'
  tag severity: 'medium'
  tag gid: 'V-42617'
  tag rid: 'SV-55345r2_rule'
  tag stig_id: 'DTASEP009'
  tag gtitle: 'DTASEP009'
  tag fix_id: 'F-48199r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
