control 'SV-214193' do
  title 'A DNS server implementation must perform data integrity verification on the name/address resolution responses the system receives from authoritative sources.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed that would result in query failure or denial of service. Data integrity verification must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching DNS servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations."
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Validate that DNSSEC validation is enabled by navigating to Data Management >> DNS >> Grid DNS properties.

Note: DNSSEC validation is only applicable on a grid member where recursion is active.

Toggle Advanced Mode click on "DNSSEC" tab.
When complete, click "Cancel" to exit the "Properties" screen.

If both "Enable DNSSEC" and "Enable DNSSEC validation" are not enabled, this is a finding.'
  desc 'fix', 'DNSSEC validation is enabled by navigating to Data Management >> DNS >> Grid DNS properties.

Toggle Advanced Mode click on "DNSSEC" tab.
Enable both "Enable DNSSEC" and "Enable DNSSEC validation".
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15408r295842_chk'
  tag severity: 'medium'
  tag gid: 'V-214193'
  tag rid: 'SV-214193r612370_rule'
  tag stig_id: 'IDNS-7X-000540'
  tag gtitle: 'SRG-APP-000425-DNS-000058'
  tag fix_id: 'F-15406r295843_fix'
  tag 'documentable'
  tag legacy: ['SV-83071', 'V-68581']
  tag cci: ['CCI-002467']
  tag nist: ['SC-21']
end
