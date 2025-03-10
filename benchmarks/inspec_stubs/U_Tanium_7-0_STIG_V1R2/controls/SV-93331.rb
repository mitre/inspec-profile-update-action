control 'SV-93331' do
  title 'Flaw remediation Tanium applications must employ automated mechanisms to determine the state of information system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans not covered by HBSS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).'
  desc 'Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the flaw remediation application may have automated mechanisms that perform automated scans for security-relevant software updates (e.g., patches, service packs, and hot fixes) and security vulnerabilities of the information system components being monitored. For example, a method of compliance would be an integrated solution incorporating continuous scanning using HBSS and periodic scanning using other tools as specified in the requirement.'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Scheduled Actions" tab.

Look for a scheduled action targeting all machines that is titled either "Patch - Distribute Scan Configuration" or "Patch Management - Run Patch Scan".

If there is no Scheduled Action for patching or the Scheduled Action is less frequent than every "30" days, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Scheduled Actions" tab.

Look for a scheduled action targeting all machines that is titled either "Patch - Distribute Scan Configuration" or "Patch Management - Run Patch Scan".

Make sure the action is enabled, and configure it to reissue at a minimum, every "30" days.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78195r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78625'
  tag rid: 'SV-93331r1_rule'
  tag stig_id: 'TANS-CN-000018'
  tag gtitle: 'SRG-APP-000270'
  tag fix_id: 'F-85361r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
