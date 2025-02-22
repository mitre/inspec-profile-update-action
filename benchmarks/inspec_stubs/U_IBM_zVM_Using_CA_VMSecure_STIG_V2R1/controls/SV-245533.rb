control 'SV-245533' do
  title 'The IBM z/VM CHECKSUM statement must be included in the TCP/IP configuration file.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed which would result in query failure or denial of service. Data integrity verification must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations.

The CHECKSUM statement is a TCP/IP configuration file statement that instructs the TCPIP virtual machine to reenable TCP checksum testing on incoming messages."
  desc 'check', 'Examine the “TCP/IP” configuration file.

If there is no “CHECKSUM” statement in the “TCP/IP” configuration file, this is a finding.'
  desc 'fix', 'Configure the “TCP/IP” configuration file to include a “CHECKSUM” statement.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-48808r755027_chk'
  tag severity: 'medium'
  tag gid: 'V-245533'
  tag rid: 'SV-245533r755029_rule'
  tag stig_id: 'IBMZ-VM-001140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48764r755028_fix'
  tag 'documentable'
  tag legacy: ['SV-93657', 'V-78951']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
