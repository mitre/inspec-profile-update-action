control 'SV-96105' do
  title 'The WebSphere Application Server must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'Export grade encryption suites are not strong and do not meet DoD requirements. The encryption for the session becomes easy for the attacker to break. Do not use export grade encryption. Information on disabling export ciphers can be found in Knowledge Center at this link: http://www.ibm.com/support/knowledgecenter/SS7K4U_8.5.5/com.ibm.websphere.ihs.doc/ihs/rihs_ciphspec.html'
  desc 'check', 'From the administrative console, navigate to Security >> SSL certificate and key management >> SSL configurations >> [Name] >> for each SSL Configuration

Select "Quality of protection (QoP) settings".

Under "Cipher suite" settings, if any of the ciphers contained in the "Selected ciphers" box" contain "EXPORT" in their name, this is a finding.'
  desc 'fix', 'From the administrative console, navigate to Security >> SSL certificate and key management >> SSL configurations >> [Name] >> for each SSL configuration

Select "Quality of protection (QoP) settings" under "Cipher suite" settings.

Identify any ciphers that include "EXPORT" in their name.

Remove the cipher by selecting the cipher.

Click "Remove" button.

Click "OK".

Recycle the DMGR and sync the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81101r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81391'
  tag rid: 'SV-96105r1_rule'
  tag stig_id: 'WBSP-AS-001610'
  tag gtitle: 'SRG-APP-000439-AS-000274'
  tag fix_id: 'F-88177r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
