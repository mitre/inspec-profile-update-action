control 'SV-60203' do
  title 'The AirWatch MDM Server must provide the administrative functionality to specify a list of approved applications that must be installed on the mobile device and cannot be removed by the user.'
  desc 'DoD can perform due diligence on sources of software to mitigate the risk that malicious software is introduced to those sources.  Therefore, if software is downloaded from a DoD-approved source, then it is less likely to be malicious than if it is downloaded from an unapproved source.  To prevent access to unapproved sources, the operating system in most cases can be configured to disable user access to public application stores.  In some cases, some applications are required for secure operation of the mobile devices controlled by the AirWatch MDM Server.  In these cases, the ability for users to remove the application is needed as to ensure proper secure operations of the device.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure there is administrative functionality to specify a list of approved applications that must be installed on the mobile device and cannot be removed by the user. If this function is not present, this is a finding.

To verify Required Application Lists on Administration console: (1) click on "Menu" in top tool bar, (2) click on "Applications" under "Catalog" heading, on left-hand tool bar (3) click on "Application Groups", and (4) click on applicable "Required Applications" group, to verify that correct information is set.'
  desc 'fix', 'Configure the AirWatch MDM Server so it has the administrative functionality to specify a list of approved applications that must be installed on the mobile device and cannot be removed by the user.

To create Required Applications Groups in Administration console:  (1) click on "Menu" in top tool bar, (2) click on "Applications" under "Catalog" heading, and on left-hand tool bar (3) click on "Application Groups", (4) click "Add Group", and under drop-down box labeled "Type" (5) choose "Blacklist".  (6) Choose Android or iOS platform, and (7) add applicable applications. (8) Click "Next" to review summary and (9) click "Finish".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50097r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47331'
  tag rid: 'SV-60203r1_rule'
  tag stig_id: 'ARWA-02-000187'
  tag gtitle: 'SRG-APP-135-MDM-150-MDM'
  tag fix_id: 'F-51037r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
