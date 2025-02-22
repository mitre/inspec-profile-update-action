control 'SV-81407' do
  title 'Oracle JRE 8 must disable the dialog enabling users to grant permissions to execute signed content from an untrusted authority.'
  desc 'Java applets exist both signed and unsigned.  Even for signed applets, there can be many sources, some of which may be purveyors of malware.  Applet sources considered trusted can have their information populated into the browser, enabling Java to validate applets against trusted sources.  Permitting execution of signed Java applets from untrusted sources may result in acquiring malware, and risks system modification, invasion of privacy, or denial of service.'
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

Navigate to the system-level “deployment.properties” file for Java.

 /etc/.java/deployment/deployment.properties

If the key, “deployment.security.askgrantdialog.notinca=false” is not present, this is a finding.

If the key, “deployment.security.askgrantdialog.notinca.locked” is not present, this is a finding.

If the key “deployment.security.askgrantdialog.notinca” exists and is set to true, this is a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Disable the “Allow user to grant permissions to content from an untrusted authority” feature.

Navigate to the system-level “deployment.properties” file for JRE.

 /etc/.java/deployment/deployment.properties

Add the key “deployment.security.askgrantdialog.notinca=false” to the deployment.properties file.
Add the key “deployment.security.askgrantdialog.notinca.locked” to the deployment.properties file.'
  impact 0.5
  ref 'DPMS Target JRE 8 (1.8)'
  tag check_id: 'C-67553r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66917'
  tag rid: 'SV-81407r1_rule'
  tag stig_id: 'JRE8-UX-000080'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-73017r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
