control 'SV-245535' do
  title 'IBM z/OS TCPIP.DATA configuration statement must contain the DOMAINORIGIN or DOMAIN specified for each TCP/IP defined.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed which would result in query failure or denial of service. Data origin authentication verification must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations.

This is not applicable if DNSSEC is not implemented on the local network."
  desc 'check', "Refer to the Data configuration file specified on the SYSTCPD DD statement in the TCPIP started task JCL.

Note:
If GLOBALTCPIPDATA is specified, any TCPIP.DATA statements contained in the specified file or data set take precedence over any TCPIP.DATA statements found using the appropriate environment's (native MVS or z/OS UNIX) search order.

If GLOBALTCPIPDATA is not specified, the appropriate environment's (Native MVS or z/OS UNIX) search order is used to locate TCPIP.DATA.

If the configuration statements specified in the TCP/IP Data configuration file guidance are true, this is not a finding.

DOMAINORIGIN/DOMAIN (The DOMAIN statement is functionally equivalent to the DOMAINORIGIN Statement)"
  desc 'fix', "Configure the TCPIP.DATA file to include the following:

DOMAINORIGIN/DOMAIN - Specifies the default domain name used for DNS searches.   

Note:
If GLOBALTCPIPDATA is specified, any TCPIP.DATA statements contained in the specified file or data set take precedence over any TCPIP.DATA statements found using the appropriate environment's (native MVS or z/OS UNIX) search order.

If GLOBALTCPIPDATA is not specified, the appropriate environment's (Native MVS or z/OS UNIX) search order is used to locate TCPIP.DATA."
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-48810r768732_chk'
  tag severity: 'medium'
  tag gid: 'V-245535'
  tag rid: 'SV-245535r768734_rule'
  tag stig_id: 'ACF2-TC-000090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48766r768733_fix'
  tag 'documentable'
  tag legacy: ['SV-107023', 'V-97919']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
