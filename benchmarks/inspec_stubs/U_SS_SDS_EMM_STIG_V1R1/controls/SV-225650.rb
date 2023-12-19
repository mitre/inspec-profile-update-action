control 'SV-225650' do
  title 'The Samsung SDS EMM server must be maintained at a supported version.'
  desc 'Versions of Samsung SDS EMM are maintained by Samsung SDS for specific periods of time. Unsupported versions will not receive security updates for new vulnerabilities which leaves them subject to exploitation.

SFR ID: FPT_TUD_EXT.1'
  desc 'check', 'Verify the installed version of the Samsung SDS EMM server is a supported version. A list of supported versions of EMM can be found at http://support.samsungsds.com. (Note: An account is needed to access this web page. The site EMM system administrator should be able to access the site and print the list for the reviewer/auditor.)

For viewing the installed version of EMM, on the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Check the version by version number and deploy date at the bottom left on the screen.
3. Verify the version is on the list of supported versions on the Samsung SDS website.

If the installed version of Samsung SDS EMM server is not a supported version, this is a finding.'
  desc 'fix', 'For viewing the installed version of EMM, on the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Check the version by version number and deploy date at the bottom left on the screen.
3. Verify the installed version of the Samsung SDS EMM server is a supported version. A list of supported versions of EMM can be found at http://support.samsungsds.com. (Note: An account is needed to access this web page. The site EMM system administrator should be able to access the site and print the list for the reviewer/auditor.)
4. Install a supported version of SDS EMM using Samsung SDS published procedures. To get the EMM Installer and apk file, contact the EMM technical support team.'
  impact 0.7
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27351r547735_chk'
  tag severity: 'high'
  tag gid: 'V-225650'
  tag rid: 'SV-225650r547737_rule'
  tag stig_id: 'SSDS-00-000740'
  tag gtitle: 'PP-MDM-992000'
  tag fix_id: 'F-27339r547736_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
