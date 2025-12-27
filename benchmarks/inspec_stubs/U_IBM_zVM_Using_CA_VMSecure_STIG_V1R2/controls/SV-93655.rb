control 'SV-93655' do
  title 'The IBM z/VM TCP/IP NSINTERADDR statement must be present in the TCPIP DATA configuration.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed, which would result in query failure or DoS. Data origin authentication must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations. Information systems that use technologies other than the DNS to map between host/service names and network addresses provide other means to enable clients to verify the authenticity of response data.

This is not applicable if DNSSEC is not implemented on the local network."
  desc 'check', 'Examine the “TCPIP DATA” configuration file.

If there is no “NSINTERADDR” statement in the “TCPIP DATA” configuration file, this is a finding.'
  desc 'fix', 'Configure the “NSINTERADDR” statement in the “TCPIP DATA” configuration file to an appropriate address.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78535r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78949'
  tag rid: 'SV-93655r1_rule'
  tag stig_id: 'IBMZ-VM-001130'
  tag gtitle: 'SRG-OS-000399-GPOS-00178'
  tag fix_id: 'F-85699r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002465']
  tag nist: ['SC-21']
end
