control 'SV-222405' do
  title 'The application must ensure if a OneTimeUse element is used in an assertion, there is only one of the same used in the Conditions element portion of an assertion.'
  desc '<0> [object Object]'
  desc 'check', 'Ask the application representative for the design document.

Review the design document for web services using SAML assertions.

If the application does not utilize SAML assertions, this check is not applicable.

Examine the contents of a SOAP message using the OneTimeUse element; all messages should contain only one instance of a <OneTimeUse> element in a SAML assertion. This can be accomplished using a protocol analyzer such as Wireshark.

If SOAP message uses more than one, OneTimeUse element in a SAML assertion, this is a finding.'
  desc 'fix', 'When using OneTimeUse elements in a SAML assertion only allow one, OneTimeUse element to be used in the conditions element of a SAML assertion.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24075r493123_chk'
  tag severity: 'medium'
  tag gid: 'V-222405'
  tag rid: 'SV-222405r508029_rule'
  tag stig_id: 'APSC-DV-000250'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-24064r493124_fix'
  tag legacy: ['SV-83913', 'V-69291']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
