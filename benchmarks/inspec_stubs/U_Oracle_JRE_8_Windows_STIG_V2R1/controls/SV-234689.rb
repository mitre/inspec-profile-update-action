control 'SV-234689' do
  title 'Oracle JRE 8 must lock the dialog enabling users to grant permissions to execute signed content from an untrusted authority.'
  desc 'Java applets exist both signed and unsigned. Even for signed applets, there can be many sources, some of which may be purveyors of malware. Applet sources considered trusted can have their information populated into the browser, enabling Java to validate applets against trusted sources. Permitting execution of signed Java applets from untrusted sources may result in acquiring malware, and risks system modification, invasion of privacy, or denial of service.

Ensuring users cannot change settings contributes to a more consistent security profile.'
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

Navigate to the system-level "deployment.properties" file for JRE.

<Windows Directory>\\Sun\\Java\\Deployment\\deployment.properties
- or -
<JRE Installation Directory>\\Lib\\deployment.properties

If the key "deployment.security.askgrantdialog.show=false" is not present, this is a finding.

If the key "deployment.security.askgrantdialog.show.locked" is not present, this is a finding.

If the key "deployment.security.askgrantdialog.show" exists and is set to "true", this is a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Lock the "Allow user to grant permissions to content from an untrusted authority" feature.

Navigate to the system-level "deployment.properties" file for JRE.

Add the key "deployment.security.askgrantdialog.show=false" to the "deployment.properties" file.

Add the key "deployment.security.askgrantdialog.show.locked" to the "deployment.properties" file.'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37874r616123_chk'
  tag severity: 'medium'
  tag gid: 'V-234689'
  tag rid: 'SV-234689r617446_rule'
  tag stig_id: 'JRE8-WN-000090'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-37839r616124_fix'
  tag 'documentable'
  tag legacy: ['V-66951', 'SV-81441']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
