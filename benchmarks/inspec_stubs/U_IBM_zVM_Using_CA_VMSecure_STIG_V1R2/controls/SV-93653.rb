control 'SV-93653' do
  title 'The IBM z/VM TCP/IP DOMAINLOOKUP statement must be properly configured.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed, which would result in query failure or DoS. Data origin authentication must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations. Information systems that use technologies other than the DNS to map between host/service names and network addresses provide other means to enable clients to verify the authenticity of response data.

This is not applicable if DNSSEC is not implemented on the local network."
  desc 'check', 'Examine the “TCPIP DATA” configuration file.

If “DOMAINLOOKUP” statement is configured to “DNS”, this is not a finding.'
  desc 'fix', 'Configure the “DOMAINLOOKUP” statement to “DNS”.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78533r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78947'
  tag rid: 'SV-93653r1_rule'
  tag stig_id: 'IBMZ-VM-001120'
  tag gtitle: 'SRG-OS-000399-GPOS-00178'
  tag fix_id: 'F-85697r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002465']
  tag nist: ['SC-21']
end
