control 'SV-60197' do
  title 'The AirWatch MDM Server must configure the mobile device agent to prohibit the download of software from a DoD non-approved source (e.g., DoD operated mobile device application store or AirWatch MDM Server).'
  desc 'DoD can perform due diligence on sources of software to mitigate the risk that malicious software is introduced to those sources.  Therefore, if software is downloaded from a DoD-approved source, then it is less likely to be malicious than if it is downloaded from an unapproved source.  To prevent access to unapproved sources, the operating system in most cases can be configured to disable user access to public application stores.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server can configure the mobile device agent to prohibit the download of software from a DoD non-approved source (e.g., DoD operated mobile device application store or AirWatch MDM Server). If this function is not present, this is a finding.

Note that the following should take place in conjunction with application blacklisting/whitelisting as noted in applicable items within this STIG and the document: "AirWatch Mobile Application Management Guide", page 35, "Enforcing Application Security and Compliance", describing Application blacklisting/whitelisting and deployment control.

To verify applications assigned to mobile devices: (1) In administration console click on "Menu" in top tool bar, and (2) click on "Applications" under "Catalog" heading. (3) Using tabs on top toolbar Administrator can choose "Internal", "Public", or "Purchased" applications, and verify applications assigned to devices.'
  desc 'fix', 'Configure the AirWatch MDM Server so the mobile device agent is configured to prohibit the download of software from a DoD non-approved source.

For Administration console: (1) In administration console click on "Menu" in top tool bar, and (2) click on "Applications" under "Catalog" heading. (3) Using tabs on top toolbar Administrator can choose "Internal", "Public", or "Purchased" applications, (4) load or search for application and, (5) assign to devices.'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50091r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47325'
  tag rid: 'SV-60197r1_rule'
  tag stig_id: 'ARWA-02-000184'
  tag gtitle: 'SRG-APP-135-MDM-149-MDM'
  tag fix_id: 'F-51031r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
