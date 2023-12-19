control 'SV-245536' do
  title 'The IBM z/OS TCPIP.DATA configuration statement must contain the DOMAINORIGIN or DOMAIN specified for each TCP/IP defined.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed which would result in query failure or denial of service. Data origin authentication verification must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations.

This is not applicable if DNSSEC is not implemented on the local network."
  desc 'check', "Refer to the Data configuration file specified on the SYSTCPD DD statement in the TCPIP started task JCL.

Note:
If GLOBALTCPIPDATA is specified, any TCPIP.DATA statements contained in the specified file or data set take precedence over any TCPIP.DATA statements found using the appropriate environment's (native MVS or z/OS UNIX) search order.

If GLOBALTCPIPDATA is not specified, the appropriate environment's (Native MVS or z/OS UNIX) search order is used to locate TCPIP.DATA.

If the DOMAINORIGIN/DOMAIN (the DOMAIN statement is functionally equivalent to the DOMAINORIGIN statement) is specified in the TCP/IP Data configuration file, this is not a finding."
  desc 'fix', "Configure the TCPIP.DATA file to include the DOMAINORIGIN/DOMAIN (the DOMAIN statement is functionally equivalent to the DOMAINORIGIN statement).   

Note:
If GLOBALTCPIPDATA is specified, any TCPIP.DATA statements contained in the specified file or data set take precedence over any TCPIP.DATA statements found using the appropriate environment's (native MVS or z/OS UNIX) search order.

If GLOBALTCPIPDATA is not specified, the appropriate environment's (Native MVS or z/OS UNIX) search order is used to locate TCPIP.DATA."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-48811r768735_chk'
  tag severity: 'medium'
  tag gid: 'V-245536'
  tag rid: 'SV-245536r768737_rule'
  tag stig_id: 'RACF-TC-000100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48767r768736_fix'
  tag 'documentable'
  tag legacy: ['SV-107469', 'V-98365']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
