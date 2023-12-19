control 'SV-253790' do
  title 'The Tanium application must employ automated mechanisms to determine the state of information system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans not covered by HBSS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).'
  desc 'Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the flow remediation application may have automated mechanisms that perform automated scans for security-relevant software updates (e.g., patches, service packs, and hot fixes) and security vulnerabilities of the information system components being monitored. For example, a method of compliance would be an integrated solution incorporating continuous scanning using HBSS and periodic scanning using other tools as specified in the requirement.'
  desc 'check', 'Note: If Tanium Patch is not licensed, another scanning solutions can be used. 

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Modules" at the top of the console.

3. Select "Patch".

4. On the left, expand the menu (three vertical dots).

5. Select "Scan Management".

If there is no "Scan Configurations" for all applicable operating systems, or if "Scan Configurations" are set with a Scan Frequency greater than 30 days, this is a finding.'
  desc 'fix', 'Note: If Tanium Patch is not licensed, another scanning solutions can be used. 

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication.

2. Click "Modules" on the top navigation banner. 

3. Click "Patch".

4. Expand the left menu.

5. Select "Scan Management".

6. Work with the Tanium administrator to create Scan Configurations that run more often than 30 days.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57242r842396_chk'
  tag severity: 'medium'
  tag gid: 'V-253790'
  tag rid: 'SV-253790r842661_rule'
  tag stig_id: 'TANS-00-001195'
  tag gtitle: 'SRG-APP-000270'
  tag fix_id: 'F-57193r842397_fix'
  tag 'documentable'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
