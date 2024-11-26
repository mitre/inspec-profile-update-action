control 'SV-55421' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan must be configured to use Insight File Reputation lookup, when scanning, set to a sensitivity level of at least 5 (Typical).'
  desc 'Antivirus software vendors use collective intelligence from sensors and cross-vector intelligence from web, email, and network threats to compile scores that reflect the likelihood of whether a file in question is malware. The collective intelligence is constantly being updated, more frequently than the typical daily antivirus signature files. With File Reputation lookup, a more real-time response to potential malicious code is realized than with the local-running antivirus software since querying the cloud-based database when a file appears to be suspicious provides up- to- the- minute intelligence. This type of protection reduces the threat protection time period from days to milliseconds, increases malware detection rates, and reduces downtime and remediation costs associated with malware attacks. Using File Reputation lookup is mandated by US CYBERCOM on DoD systems.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Insight Lookup tab, Insight Lookup, select Level -> Ensure the slider is set to "5 (Typical)" or greater.

Criteria:  If the slider is not set to "5 (Typical)" or greater, this is a finding.

Client check:  Locate the Symantec Endpoint Protection icon in the system tray.  Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Scan for Threats -> Double-click the applied policy -> Under Scan Options -> Select Insight Lookup -> Under Specify the sensitivity level -> Ensure the slider is set to "5 (Typical)" or greater.

Criteria: If the slider is not set to "5 (Typical)" or greater, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Insight Lookup tab, Insight Lookup, select Level -> Set the slider to "5 (Typical)" or greater.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48964r3_chk'
  tag severity: 'medium'
  tag gid: 'V-42693'
  tag rid: 'SV-55421r1_rule'
  tag stig_id: 'DTASEP046'
  tag gtitle: 'DTASEP046'
  tag fix_id: 'F-48278r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
