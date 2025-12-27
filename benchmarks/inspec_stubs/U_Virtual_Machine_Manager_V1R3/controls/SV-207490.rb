control 'SV-207490' do
  title 'The VMM must request data integrity verification on the name/address resolution responses the system receives from authoritative sources.'
  desc "If data origin authentication and data integrity verification is not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed that would result in query failure or denial of service. Data integrity verification must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. VMMs that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations.

This is not applicable if DNSSEC is not implemented on the local network."
  desc 'check', 'Verify the VMM requests data integrity verification on the name/address resolution responses the system receives from authoritative sources.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to request data integrity verification on the name/address resolution responses the system receives from authoritative sources.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7747r365874_chk'
  tag severity: 'medium'
  tag gid: 'V-207490'
  tag rid: 'SV-207490r854664_rule'
  tag stig_id: 'SRG-OS-000400-VMM-001610'
  tag gtitle: 'SRG-OS-000400'
  tag fix_id: 'F-7747r365875_fix'
  tag 'documentable'
  tag legacy: ['SV-71541', 'V-57281']
  tag cci: ['CCI-002466']
  tag nist: ['SC-21']
end
