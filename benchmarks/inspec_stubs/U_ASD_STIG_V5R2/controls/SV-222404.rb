control 'SV-222404' do
  title 'The application must use both the NotBefore and NotOnOrAfter elements or OneTimeUse element when using the Conditions element in a SAML assertion.'
  desc '<0> [object Object]'
  desc 'check', 'Ask the application representative for the design document.

Review the design document for web services using SAML assertions.

If the application does not utilize SAML assertions, this check is not applicable.

Examine the contents of a SOAP message using the <Conditions> element; all messages should contain the <NotBefore> and <NotOnOrAfter> or <OneTimeUse> element when in a SAML Assertion. This can be accomplished using a protocol analyzer such as Wireshark.

If SOAP using the <Conditions> element does not contain <NotBefore> and <NotOnOrAfter> or <OneTimeUse> elements, this is a finding.'
  desc 'fix', 'Design and configure the application to implement the use of the <NotBefore> and <NotOnOrAfter> or <OneTimeUse> when using the <Conditions> element in a SAML assertion.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24074r493120_chk'
  tag severity: 'high'
  tag gid: 'V-222404'
  tag rid: 'SV-222404r508029_rule'
  tag stig_id: 'APSC-DV-000240'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-24063r493121_fix'
  tag legacy: ['V-69289', 'SV-83911']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
