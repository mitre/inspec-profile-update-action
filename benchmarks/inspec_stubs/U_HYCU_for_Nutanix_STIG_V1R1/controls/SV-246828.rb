control 'SV-246828' do
  title 'The HYCU VM console must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the administrator prior to the device allowing the administrator access to the network device. This provides assurance that the administrator has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the administrator, DoD will not comply with system use notifications required by law.'
  desc 'check', 'Log on to the HYCU VM console and verify the banner setting is in use in the "/etc/ssh/sshd_config" file by executing the following command:
grep Banner /etc/ssh/sshd_config

If the banner is not set to "/etc/issue.net", this is a finding.

Verify "/etc/issue.net" contains valid DoD notice text by executing the following command:
sudo cat /etc/issue.net

If DoD Notice is not present in the "/etc/issue.net" file, this is a finding.

Open the HYCU Web UI logon page and verify the mandatory notice is present on the Welcome page.

If the mandatory notice is not present at HYCU Web UI welcome page, this is a finding.'
  desc 'fix', 'The GUI logon page welcome message and look of the logon can be changed by following the procedure below:

1. Open a remote session to the HYCU backup controller:
ssh hycu@<HYCUBackupControllerIPAddress>

2. Copy custom images to the custom-images folder at the following location:
/opt/grizzly/www/webapp/resources/

3. Open the "customBranding.json" file from the following location:
/opt/grizzly/www/webapp/

4. In the customBranding.json file, do the following:
a. To modify the images, specify the names of the custom files added to the custom-images folder. The logon page image recommended size is 1574x1920.
b. To modify the welcome message, replace "customWelcomeTitle" and "customWelcomeSubtitle" with the desired text.

5. Perform a hard reload of the HYCU Web UI page in the web browser.

The console and ssh logon can be configured to display the DoD banner by modifying "/etc/issue.net" with the required text and editing the "/etc/ssh/sshd_config" file to uncomment the banner keyword and configure it to point to "/etc/issue" as shown below:
banner=/etc/issue.net'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50260r768146_chk'
  tag severity: 'medium'
  tag gid: 'V-246828'
  tag rid: 'SV-246828r768148_rule'
  tag stig_id: 'HYCU-AC-000010'
  tag gtitle: 'SRG-APP-000069-NDM-000216'
  tag fix_id: 'F-50214r768147_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
