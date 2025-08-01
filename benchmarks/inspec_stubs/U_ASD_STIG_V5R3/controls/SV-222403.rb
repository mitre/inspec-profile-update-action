control 'SV-222403' do
  title 'The application must use the NotOnOrAfter condition when using the SubjectConfirmation element in a SAML assertion.'
  desc '<0> [object Object]'
  desc 'check', 'Ask the application representative for the design document.

Review the design document for web services using SAML assertions.

If the application does not utilize SAML assertions, this check is not applicable.

Examine the contents of a SOAP message using the <SubjectConfirmation> element. All messages should contain the <NotOnOrAfter> element. This can be accomplished if the application allows the ability to view XML messages or via a protocol analyzer like Wireshark.

If SOAP messages do not contain <NotOnOrAfter> elements, this is a finding.'
  desc 'fix', 'Design and configure the application to use the <NotOnOrAfter> condition when using the <SubjectConfirmation> element in a SAML assertion.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24073r493117_chk'
  tag severity: 'high'
  tag gid: 'V-222403'
  tag rid: 'SV-222403r879519_rule'
  tag stig_id: 'APSC-DV-000230'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-24062r493118_fix'
  tag legacy: ['SV-83909', 'V-69287']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
