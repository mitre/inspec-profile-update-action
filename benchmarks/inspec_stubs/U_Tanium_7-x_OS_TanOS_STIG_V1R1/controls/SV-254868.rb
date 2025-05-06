control 'SV-254868' do
  title 'The Tanium operating system (TanOS) must perform data integrity verification on the name/address resolution responses the system receives from authoritative sources.'
  desc "If data origin authentication and data integrity verification is not performed, the resultant response could be forged, it may have come from a poisoned cache, the packets could have been intercepted without the resolver's knowledge, or resource records could have been removed, which would result in query failure or denial of service. Data integrity verification must be performed to thwart these types of attacks.

Each client of name resolution services either performs this validation on its own, or has authenticated channels to trusted validation providers. Information systems that provide name and address resolution services for local clients include, for example, recursive resolving or caching Domain Name System (DNS) servers. DNS client resolvers either perform validation of DNSSEC signatures, or clients use authenticated channels to recursive resolvers that perform such validations. 

This applies to operating systems that have integrated DNS clients."
  desc 'check', '1. Work with a systems administrator to determine a designated Name Server that performs data integrity checks.

2. Sign in to the TanOS console as a user with the tanadmin role.

3. Enter "A" to go to the "Appliance Configuration" menu.

4. Enter "1" to go to the "Hostname/DNS Configuration" menu.

5. Enter "2", if the ip address shown is not the designated Name Server determined in step 1. This is a finding.'
  desc 'fix', '1. Work with a systems administrator to determine a designated Name Server that performs data integrity checks.

2. Sign in to the TanOS console as a user with the tanadmin role.

3. Enter "A" to go to the "Appliance Configuration" menu.

4. Enter "1" to go to the "Hostname/DNS Configuration" menu.

5. Enter "2" and follow the prompts to modify the DNS server configuration.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58481r866143_chk'
  tag severity: 'medium'
  tag gid: 'V-254868'
  tag rid: 'SV-254868r866145_rule'
  tag stig_id: 'TANS-OS-001325'
  tag gtitle: 'SRG-OS-000401'
  tag fix_id: 'F-58425r866144_fix'
  tag 'documentable'
  tag cci: ['CCI-002467']
  tag nist: ['SC-21']
end
