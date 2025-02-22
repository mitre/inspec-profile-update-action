control 'SV-207492' do
  title 'The VMM must perform data origin verification authentication on the name/address resolution responses the system receives from authoritative sources.'
  desc "If data origin authentication and data integrity verification are not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed which would result in query failure or denial of service. Data origin authentication verification must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. VMMs that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations.

This is not applicable if DNSSEC is not implemented on the local network."
  desc 'check', 'Verify the VMM performs data origin verification authentication on the name/address resolution responses the system receives from authoritative sources.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to perform data origin verification authentication on the name/address resolution responses the system receives from authoritative sources.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7749r365880_chk'
  tag severity: 'medium'
  tag gid: 'V-207492'
  tag rid: 'SV-207492r854666_rule'
  tag stig_id: 'SRG-OS-000402-VMM-001630'
  tag gtitle: 'SRG-OS-000402'
  tag fix_id: 'F-7749r365881_fix'
  tag 'documentable'
  tag legacy: ['V-57285', 'SV-71545']
  tag cci: ['CCI-002468']
  tag nist: ['SC-21']
end
