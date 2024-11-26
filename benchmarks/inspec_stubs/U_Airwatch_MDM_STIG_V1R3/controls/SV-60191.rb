control 'SV-60191' do
  title 'The AirWatch MDM Server must configure the mobile device to prohibit the mobile device user from installing unapproved applications.'
  desc 'The operating system must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.  The installation and execution of unauthorized software on an operating system may allow the application to obtain sensitive information or further compromise the system.  Preventing a user from installing unapproved applications mitigates this risk.  All OS core applications, third-party applications, and carrier installed applications must be approved.  In this case, applications include any applets, browse channel apps, and icon apps.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server can configure the mobile device to prohibit the mobile device user from installing unapproved applications. If this function is not present, this is a finding.

Note that the following should take place in conjunction with application blacklisting/whitelisting as noted in the "AirWatch Mobile Application Management Guide", page 35, "Enforcing Application Security and Compliance", and applicable items within this STIG.

Apple iOS MOS:
To verify Application blacklists on Administration console: (1) click on "Menu" in top tool bar, (2) click on "Applications" under "Catalog" heading, and (3) on left-hand tool bar click on "Application Groups". (4) Click on applicable group, and verify that correct information is set.'
  desc 'fix', 'Configure the AirWatch MDM Server so the mobile device is configured to prohibit the mobile device user from installing unapproved applications.  

To set Application Blacklists in Administration console:  (1) click on "Menu" in top tool bar, (2) click on "Applications" under "Catalog" heading, and on left-hand tool bar (3) click on "Application Groups".  (4) Click "Add Group", and under drop-down box labeled "Type" choose "Blacklist".  (5) Choose Android or iOS platform, and (6) add applicable applications. (7) Click "Next" to review summary and (8) click "Finish".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50085r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47319'
  tag rid: 'SV-60191r1_rule'
  tag stig_id: 'ARWA-02-000181'
  tag gtitle: 'SRG-APP-135-MDM-148-MAM'
  tag fix_id: 'F-51025r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
