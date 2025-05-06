control 'SV-80491' do
  title 'Trend Deep Security must alert the ISSO, ISSM, and other individuals designated by the local organization when the following Indicators of Compromise (IOCs) or potential compromise are detected: real-time intrusion detection; threats identified by authoritative sources (e.g., CTOs); and Category I, II, IV, and VII incidents in accordance with CJCSM 6510.01B.'
  desc 'When a security event occurs, the application that has detected the event must immediately notify the appropriate support personnel so they can respond appropriately. 

Alerts may be generated from a variety of sources, including, audit records or inputs from malicious code protection mechanisms, intrusion detection, or prevention mechanisms. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. Individuals designated by the local organization to receive alerts may include, for example, system administrators, mission/business owners, or system owners.

IOCs are forensic artifacts from intrusions that are identified on organizational information systems (at the host or network level). IOCs provide organizations with valuable information on objects or information systems that have been compromised. These indicators reflect the occurrence of a compromise or a potential compromise.

This requirement applies to applications that provide monitoring capability for unusual/unauthorized activities including, but are not limited to, host-based intrusion detection, anti-virus, and malware applications.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure ISSO, ISSM, and other individuals designated by the local organization are alerted when the following Indicators of Compromise (IOCs) or potential compromise are detected: real time intrusion detection; threats identified by authoritative sources (e.g., CTOs); and Category I, II, IV, and VII incidents in accordance with CJCSM 6510.01B.

1. Analyze the system using the Administration >> System Settings >> Alerts tab. 
Review the email address listed in the “Alert Event Forwarding (From The Manager).” 

If this email address is not present or does not belong to a distribution group for system administrators and ISSOs, this is a finding.

2. Select Computers from the top menu and double click on any computer from the “Computers” window. Click the “Intrusion Prevention” option and review the Configuration setting under the “General” tab. 

If “Intrusion Prevention” is set to “Off”, this is a finding

3. Select a rule from the “Assigned Intrusion Prevention Rules” and double click to bring up the properties.  Click “Options” and verify that the “Alert” tab is set to “On”. 

If “Alert” is set to “Off”, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to alert the ISSO, ISSM, and other individuals designated by the local organization when the following Indicators of Compromise (IOCs) or potential compromise are detected: real-time intrusion detection; threats identified by authoritative sources (e.g., CTOs); and Category I, II, IV, and VII incidents in accordance with CJCSM 6510.01B.

Configure Events and Alerts to notify the SA and ISSO using the Administration >> System Settings >> Alerts tab. Inset a distribution email address into the “Alert Event Forwarding (From The Manager).” The distribution email address must be configured within Exchange or other email server and must associate the SA and ISSO accounts reviewing and/or managing the system.

Enable Intrusion Prevention by selecting the “Computers” tab from the top menu and double click on the computer that is to be configured from list. Click Intrusion Prevention >> General. Select “On” under “Configuration”.
Enable Alerts by selecting a rule from the “Assigned Intrusion Prevention Rules” by double clicking to bring up the properties.  Select the “Options” tab and set the “Alert” tab to “On”.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66649r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66001'
  tag rid: 'SV-80491r1_rule'
  tag stig_id: 'TMDS-00-000345'
  tag gtitle: 'SRG-APP-000471'
  tag fix_id: 'F-72077r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
