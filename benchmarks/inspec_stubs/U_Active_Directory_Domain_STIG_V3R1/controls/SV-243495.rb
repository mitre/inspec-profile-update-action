control 'SV-243495' do
  title 'A VPN must be used to protect directory network traffic for directory service implementation spanning enclave boundaries.'
  desc 'The normal operation of AD requires the use of IP network ports and protocols to support queries, replication, user authentication, and resource authorization services. At a minimum, LDAP or LDAPS is usually required for communication with every domain controller. DoD Ports, Protocols, and Services Management (PPSM) policy restricts the use of LDAP, LDAPS, and many of the AD-related protocols across enclave boundaries because vulnerabilities exist in the protocols or service implementations. To comply with the restrictions and address the vulnerabilities, a VPN implementation may be used. If AD data traverses enclave network boundaries using a vulnerable protocol or service without the protection provided by a VPN, that data might be subject to tampering or interception.

Further Policy Details: Implement a VPN or other network protection solution in accordance with the Network Infrastructure STIG that protects AD data in transit across DoD enclave boundaries. VPN requirements will include registering the VPN and connection points with the PPSM. Current guidance is available in the Network Infrastructure STIG and from the PPSM.'
  desc 'check', "1. Review the site's network diagram(s) to determine if domain controllers for the domain are located in multiple enclaves. The object is to determine if network traffic is traversing enclave network boundaries.

2. Request information about RODC or ADAM instances are installed. In particular, request details of Active Diretory functionality installed or extended into the DMZ or configured/allowed to cross the sites outbound firewall boundary. Ensure communications and replication traffic is encrypted.

3. If domain controllers are not located in multiple enclaves, then this check is not applicable.

4. If domain controllers are located in multiple enclaves, verify that a VPN is used to transport the network traffic (replication, user logon, queries, etc.).

5. If a VPN solution is not used to transport directory network traffic across enclave boundaries, then this is a finding.

6. If the ADAM mode is in use and a migration plan for converting to RODC is not in place, then this is a finding."
  desc 'fix', 'Implement a VPN or other network protection solution in accordance with the Network Infrastructure STIG that protects AD data in transit across DoD enclave boundaries.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46770r723518_chk'
  tag severity: 'medium'
  tag gid: 'V-243495'
  tag rid: 'SV-243495r723520_rule'
  tag stig_id: 'DS00.1140_AD'
  tag gtitle: 'SRG-OS-000423'
  tag fix_id: 'F-46727r723519_fix'
  tag 'documentable'
  tag legacy: ['V-8522', 'SV-30991']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
