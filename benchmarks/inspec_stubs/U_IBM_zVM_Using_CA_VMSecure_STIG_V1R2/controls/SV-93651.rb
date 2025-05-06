control 'SV-93651' do
  title 'The IBM z/VM TCP/IP NSLOOKUP statement for UFT servers must be properly configured.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed, which would result in query failure or DoS. Data origin authentication must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations. Information systems that use technologies other than the DNS to map between host/service names and network addresses provide other means to enable clients to verify the authenticity of response data.

This is not applicable if DNSSEC is not implemented on the local network."
  desc 'check', 'Examine the “UFTD CONFIG” file.

If “NSLOOKUP” statement is “YES”, this is not a finding.'
  desc 'fix', 'Configure the “NSLOOKUP” statement in the “UFTD CONFIG” file to “YES”.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78531r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78945'
  tag rid: 'SV-93651r1_rule'
  tag stig_id: 'IBMZ-VM-001110'
  tag gtitle: 'SRG-OS-000399-GPOS-00178'
  tag fix_id: 'F-85695r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002465']
  tag nist: ['SC-21']
end
