control 'SV-223153' do
  title 'FireFox is configured to ask which certificate to present to a web site when a certificate is required.'
  desc 'When a web site asks for a certificate for user authentication, Firefox must be configured to have the user choose which certificate to present. Websites within DOD require user authentication for access which increases security for DoD information. Access will be denied to the user if certificate management is not configured.'
  desc 'check', 'Type "about:config" in the browser address bar. Verify  Preference Name "security.default_personal_cert" is set to "Ask Every Time" and is locked to prevent the user from altering.

Criteria: If the value of "security.default_personal_cert" is set incorrectly or is not locked, then this is a finding.'
  desc 'fix', 'Set the value of "security.default_personal_cert" to "Ask Every Time".  Use the Mozilla.cfg file to lock the preference so users cannot change it.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24826r531276_chk'
  tag severity: 'medium'
  tag gid: 'V-223153'
  tag rid: 'SV-223153r612236_rule'
  tag stig_id: 'DTBF050'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-24814r531277_fix'
  tag 'documentable'
  tag legacy: ['SV-16707', 'V-15768']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
