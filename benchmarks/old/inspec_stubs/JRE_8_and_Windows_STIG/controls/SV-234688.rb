control 'SV-234688' do
  title 'Oracle JRE 8 must disable the dialog enabling users to grant permissions to execute signed content from an untrusted authority.'
  desc 'Java applets exist both signed and unsigned.  Even for signed applets, there can be many sources, some of which may be purveyors of malware.  Applet sources considered trusted can have their information populated into the browser, enabling Java to validate applets against trusted sources.  Permitting execution of signed Java applets from untrusted sources may result in acquiring malware, and risks system modification, invasion of privacy, or denial of service.'
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

Navigate to the system-level "deployment.properties" file for Java.

<Windows Directory>\\Sun\\Java\\Deployment\\deployment.properties
- or -
<JRE Installation Directory>\\Lib\\deployment.properties

If the key "deployment.security.askgrantdialog.notinca=false" is not present, this is a finding.

If the key "deployment.security.askgrantdialog.notinca.locked" is not present, this is a finding.

If the key "deployment.security.askgrantdialog.notinca" exists and is set to "true", this is a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Disable the "Allow user to grant permissions to content from an untrusted authority" feature.

Navigate to the system-level "deployment.properties" file for JRE.

Add the key "deployment.security.askgrantdialog.notinca=false" to the "deployment.properties" file.

Add the key "deployment.security.askgrantdialog.notinca.locked" to the "deployment.properties" file.'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37873r616120_chk'
  tag severity: 'medium'
  tag gid: 'V-234688'
  tag rid: 'SV-234688r617446_rule'
  tag stig_id: 'JRE8-WN-000080'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-37838r616121_fix'
  tag 'documentable'
  tag legacy: ['V-66949', 'SV-81439']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
