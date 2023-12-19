control 'SV-252200' do
  title 'The HPE Nimble must be running an operating system release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'Log in to https://infosight.hpe.com using HPE Passport credentials.

Click on the Main Menu icon in the upper left corner. Select Resources >> Alletra 6000, Nimble Storage >> Documentation.

Determine current array OS version using User Interface (UI).

Refer to Nimble "GUI Administration Guide" Version: NOS 5.2.x, section "Hardware and Software Updates", subsection "Find the Array OS Version" to determine the version of the OS that is currently in use by the array.

Determine available array OS update versions using InfoSight.

*Any version of Nimble OS software greater than the "current array OS version" might qualify to be an update to the "current array OS version". The option exists to bypass several releases to come up to the newest available release depending upon requirements.

*Call HPE Support with any questions about choosing an appropriate release or the process to upgrade a release.

- Follow above instructions to log in to HPE InfoSight.
- Choose a "Software Version" from the left panel equal to or greater than the current array OS version. For example, 5.2.x would be equal to the current version and 5.3.x would be greater than the current version.
- Open the Release Notes document for each version that is greater than the current array OS version. For example, "NimbleOS Release Notes Version NOS 5.2.1.700" is greater than NOS 5.2.1.600.
- Review the entire release notes document.
- Determine if this is a release should be used for an upgrade.
- Confirm that the "From Version", for example 5.2.1.600, can be used to go to the version for which the release notes are applicable; for example 5.2.1.700.

If the operating system version is no longer supported by the vendor, this is a finding.'
  desc 'fix', 'To upgrade to a supported version, type "software --list". 

Select the last version listed with at least number 5.2.x.

Type "software --download <version<, where <version< is the version selected. 

After the download is complete, type "software --update" and accept the terms and conditions.

The update progress can be monitored using "software --update_status". Once finished, use "version" to verify that the new software has been installed correctly.'
  impact 0.7
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55656r817263_chk'
  tag severity: 'high'
  tag gid: 'V-252200'
  tag rid: 'SV-252200r822498_rule'
  tag stig_id: 'HPEN-NM-000150'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-55606r817259_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
