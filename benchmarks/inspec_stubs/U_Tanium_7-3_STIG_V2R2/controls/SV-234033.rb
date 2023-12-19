control 'SV-234033' do
  title 'Tanium must employ a deny-all, permit-by-exception (whitelist) policy to allow the execution of authorized software programs.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Verification of whitelisted software can occur either prior to execution or at system startup.

This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., HBSS and software wrappers).'
  desc 'check', 'Using a web browser on a system, which has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on the navigation button (menu) on the top left of the console.

Click on the "Protect Workbench".

Select the arrow on the left-hand side to expand the menu.

Click on "Policies".

Click on the Policy with Policy Type named "AppLocker".

If there is no policy type defined for "AppLocker", this is a finding.

Ensure the computer group containing the Tanium server is showing as online and enforced.

If the "AppLocker" policy enforcement does not contain the Tanium Server, then this is a finding.

Under Policy Details ensure the Mode is set to "Blocking".

If Mode is not set to "Blocking", this is a finding.

Under "Policy Details" expand the arrow next to "Everyone".

If all files are allowed, this is a finding.

If additional paths are found, such as %PROGRAMFILES%\\", "%WINDIR%" and "?:\\Program Files\\Tanium Server\\", they must be documented.

If additional file paths are found and have not been documented, this is a finding.

If Tanium Protect is not available, this is not applicable.'
  desc 'fix', 'Using a web browser on a system, which has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on the navigation button (menu) on the top left of the console.

Click on the "Protect Workbench".

Select the arrow on the left-hand side to expand the menu.

Click on "Policies".

Click on "New Policy".

Select "Create".

Provide a name to the policy.

Select "AppLocker" from the Policy Type menu.

Within the policy, ensure the "Blocking" radio button is selected.

In the "Allow" section, ensure the default rules for "All files located in the Program Files Folder" and "All Files located in the Windows folder" are present.

If the Tanium Server is installed in a non-default location, then a rule needs to be created to allow that file path.

All rules need Windows user set to "Everyone".

Save the Policy.

Click on "Add Enforcement".

From the dropdown, select the computer group, which contains the Tanium Server.

Select "enforce".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37218r610599_chk'
  tag severity: 'medium'
  tag gid: 'V-234033'
  tag rid: 'SV-234033r612749_rule'
  tag stig_id: 'TANS-00-000670'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-37183r610600_fix'
  tag 'documentable'
  tag legacy: ['SV-102139', 'V-92037']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
