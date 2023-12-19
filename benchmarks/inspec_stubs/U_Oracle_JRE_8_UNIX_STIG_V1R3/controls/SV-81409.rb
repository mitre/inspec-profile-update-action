control 'SV-81409' do
  title 'Oracle JRE 8 must lock the dialog enabling users to grant permissions to execute signed content from an untrusted authority.'
  desc 'Java applets exist both signed and unsigned. Even for signed applets, there can be many sources, some of which may be purveyors of malware. Applet sources considered trusted can have their information populated into the browser, enabling Java to validate applets against trusted sources. Permitting execution of signed Java applets from untrusted sources may result in acquiring malware, and risks system modification, invasion of privacy, or denial of service.

Ensuring users cannot change settings contributes to a more consistent security profile.'
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

Navigate to the system-level “deployment.properties” file for JRE.

 /etc/.java/deployment/deployment.properties

If the key, “deployment.security.askgrantdialog.show=false” is not present, this is a finding.

If the key, “deployment.security.askgrantdialog.show.locked” is not present, this is a finding.

If the key “deployment.security.askgrantdialog.show” exists and is set to true, this is a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Lock the “Allow user to grant permissions to content from an untrusted authority” feature.

Navigate to the system-level “deployment.properties” file for JRE.

 /etc/.java/deployment/deployment.properties

Add the key “deployment.security.askgrantdialog.show=false” to the deployment.properties file.
Add the key “deployment.security.askgrantdialog.show.locked” to the deployment.properties file.'
  impact 0.5
  ref 'DPMS Target JRE 8 (1.8)'
  tag check_id: 'C-67555r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66919'
  tag rid: 'SV-81409r1_rule'
  tag stig_id: 'JRE8-UX-000090'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-73019r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
