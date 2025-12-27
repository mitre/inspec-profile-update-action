control 'SV-245534' do
  title 'The IBM z/VM DOMAINSEARCH statement in the TCPIP DATA file must be configured with proper domain names for name resolution.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed which would result in query failure or denial of service. Data origin authentication verification must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations.

This is not applicable if DNSSEC is not implemented on the local network."
  desc 'check', 'Examine the "TCPIP DATA" file.

The domain specified for the "DOMAINORIGIN" statement is also used for host name resolution, as if it appeared in a "DOMAINSEARCH" statement.

If there is no "DOMAINORIGIN" or "DOMAINSEARCH" statement, this is a finding.

If the "DOMAINSEARCH" statement does not specify a proper domain, this is a finding.

If the "DOMAINORIGIN" statement does not specify a proper domain, this is a finding.'
  desc 'fix', 'Configure any statement in the "TCPIP DATA" file used during host name resolution such as "DOMAINSEARCH" statement or the "DOMAINORIGIN" statement with a proper domain name.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-48809r859039_chk'
  tag severity: 'medium'
  tag gid: 'V-245534'
  tag rid: 'SV-245534r859041_rule'
  tag stig_id: 'IBMZ-VM-001150'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48765r859040_fix'
  tag 'documentable'
  tag legacy: ['SV-93659', 'V-78953']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
