control 'SV-215307' do
  title 'AIX must request and perform data origin and integrity authentication verification on the name/address resolution responses the system receives from authoritative sources.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed, which would result in query failure or DoS. Data origin and integrity authentication must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations. Information systems that use technologies other than the DNS to map between host/service names and network addresses provide other means to enable clients to verify the authenticity of response data.

This is not applicable if DNSSEC is not implemented on the local network.

"
  desc 'check', 'Run "nslookup" command at the prompt:

#nslookup  <host_name>

Server:         10.18.12.40
Address:        10.18.12.40#53

If the Server output does not point to an authorized nameserver IPAddress, this is a finding.

Verify the nameserver is configured in "/etc/resov.conf":

# grep -i nameserver /etc/resolv.conf
nameserver 10.18.12.40

If the "nameserver" entry is not found in "/etc/resolv.conf" or does not match the ipaddress from the "nslookup" command, this is a finding.'
  desc 'fix', 'Add the following line to the "/etc/resolv.conf" file:

nameserver <nameserver_IPAddress>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16505r294372_chk'
  tag severity: 'medium'
  tag gid: 'V-215307'
  tag rid: 'SV-215307r508663_rule'
  tag stig_id: 'AIX7-00-002125'
  tag gtitle: 'SRG-OS-000399-GPOS-00178'
  tag fix_id: 'F-16503r294373_fix'
  tag satisfies: ['SRG-OS-000399-GPOS-00178', 'SRG-OS-000400-GPOS-00179', 'SRG-OS-000401-GPOS-00180', 'SRG-OS-000402-GPOS-00181']
  tag 'documentable'
  tag legacy: ['SV-101653', 'V-91555']
  tag cci: ['CCI-002465', 'CCI-002466', 'CCI-002467', 'CCI-002468']
  tag nist: ['SC-21', 'SC-21', 'SC-21', 'SC-21']
end
