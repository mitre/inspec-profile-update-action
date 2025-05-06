control 'SV-246827' do
  title 'The HYCU VM console must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.'
  desc 'check', 'Log on to the HYCU VM console and verify the banner setting is in use in the "/etc/ssh/sshd_config" file by executing the following command:
grep Banner /etc/ssh/sshd_config

If the banner is not set to "/etc/issue.net", this is a finding.

Verify "/etc/issue" contains valid DoD notice text by executing the following command:
sudo cat /etc/issue

If the DoD notice is not present in the "/etc/issue" file, this is a finding.

Open the HYCU Web UI logon page and verify the mandatory notice is present on the welcome page.

If the mandatory notice is not present at the HYCU Web UI welcome page, this is a finding.'
  desc 'fix', 'The GUI logon page welcome message and look of the logon can be changed by following the procedure below:

1. Open a remote session to the HYCU backup controller:
ssh hycu@<HYCUBackupControllerIPAddress>

2. Copy custom images to the custom-images folder at the following location:
/opt/grizzly/www/webapp/resources/

3. Open the "customBranding.json" file from the following location:
/opt/grizzly/www/webapp/

4. In the "customBranding.json file", do the following:
a. To modify the images, specify the names of the custom files added to the custom-images folder. The logon page image recommended size is 1574x1920.
b. To modify the welcome message, replace "customWelcomeTitle" and "customWelcomeSubtitle" with the desired text.

5. Perform a hard reload of the HYCU Web UI page in the web browser.

The console and ssh logon can be configured to display the DoD banner by modifying "/etc/issue" with the required text and editing the "/etc/ssh/sshd_config" file to uncomment the banner keyword and configure it to point to "/etc/issue" as shown below:
banner=/etc/issue'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50259r790580_chk'
  tag severity: 'medium'
  tag gid: 'V-246827'
  tag rid: 'SV-246827r790581_rule'
  tag stig_id: 'HYCU-AC-000009'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-50213r768144_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
