control 'SV-71035' do
  title 'The operating system must perform data origin verification authentication on the name/address resolution responses the system receives from authoritative sources.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed which would result in query failure or denial of service. Data origin authentication verification must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations.

This is not applicable if DNSSEC is not implemented on the local network."
  desc 'check', 'Verify the operating system performs data origin verification authentication on the name/address resolution responses the system receives from authoritative sources. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to perform data origin verification authentication on the name/address resolution responses the system receives from authoritative sources.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57345r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56775'
  tag rid: 'SV-71035r1_rule'
  tag stig_id: 'SRG-OS-000402-GPOS-00181'
  tag gtitle: 'SRG-OS-000402-GPOS-00181'
  tag fix_id: 'F-61671r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002468']
  tag nist: ['SC-21']
end
