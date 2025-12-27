control 'SV-254950' do
  title 'Tanium must alert the ISSO, ISSM, and other individuals designated by the local organization when the following Indicators of Compromise (IOCs) or potential compromise are detected: real time intrusion detection; threats identified by authoritative sources (e.g., CTOs); and Category I, II, IV, and VII incidents in accordance with CJCSM 6510.01B.'
  desc 'When a security event occurs, the application that has detected the event must immediately notify the appropriate support personnel so they can respond appropriately. 

Alerts may be generated from a variety of sources, including, audit records or inputs from malicious code protection mechanisms, intrusion detection, or prevention mechanisms. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. Individuals designated by the local organization to receive alerts may include, for example, system administrators, mission/business owners, or system owners.

IOCs are forensic artifacts from intrusions identified on organizational information systems (at the host or network level). IOCs provide organizations with valuable information on objects or information systems that have been compromised. These indicators reflect the occurrence of a compromise or a potential compromise.

This requirement applies to applications that provide monitoring capability for unusual/unauthorized activities including, but not limited to, host-based intrusion detection, antivirus, and malware applications.'
  desc 'check', 'Note: If THR is not licensed or used for detection then this is not applicable.  

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner.

3. Click "Threat Response". 

4. Expand the left menu.  

5. Click "Alerts".  

6. Filter on status "Unresolved". 

If any alerts are unresolved, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top navigation banner.

3. Click "Threat Response".

4. Expand the left menu. 

5. Click "Alerts". 

6. Filter on status "Unresolved". 

7. Resolve any open IOC-based alerts and change status to applicable status.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58563r867748_chk'
  tag severity: 'medium'
  tag gid: 'V-254950'
  tag rid: 'SV-254950r867750_rule'
  tag stig_id: 'TANS-AP-001250'
  tag gtitle: 'SRG-APP-000471'
  tag fix_id: 'F-58507r867749_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
