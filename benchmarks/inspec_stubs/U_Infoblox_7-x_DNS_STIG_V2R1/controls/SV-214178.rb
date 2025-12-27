control 'SV-214178' do
  title 'The Infoblox system must be configured to restrict the ability of individuals to use the DNS server to launch Denial of Service (DoS) attacks against other information systems.'
  desc 'A DoS is a condition where a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. Individuals of concern can include hostile insiders or external adversaries that have successfully breached the information system and are using the system as a platform to launch cyber attacks on third parties.

Applications and application developers must take the steps needed to ensure users cannot use an authorized application to launch DoS attacks against other systems and networks. For example, applications may include mechanisms that throttle network traffic so users are not able to generate unlimited network traffic via the application. Limiting system resources that are allocated to any user to a bare minimum may also reduce the ability of users to launch some DoS attacks.

When it comes to DoS attacks, most of the attention is paid to ensuring that systems and applications are not victims of these attacks. A DoS attack against the DNS infrastructure has the potential to cause a denial of service to all network users. As the DNS is a distributed backbone service of the Internet, numerous forms of attacks result in DoS, and they are still prevalent on the Internet today. Some potential DoS attacks against the DNS include malformed packet flood, spoofed source addresses, and distributed DoS, and the DNS can be exploited to launch amplification attacks upon other systems.

While it is true that those accountable for systems want to ensure they are not affected by a DoS attack, they also need to ensure their systems and applications are not used to launch such an attack against others. To that end, a variety of technologies exist to limit the effects of DoS attacks, such as careful configuration of resolver and recursion functionality.

DNS administrators must take the steps needed to ensure other systems and tools cannot use exploits to launch DoS attacks against other systems and networks. An example would be designing the DNS architecture to include mechanisms that throttle DNS traffic and resources so that users/other DNS servers are not able to generate unlimited DNS traffic via the application.'
  desc 'check', 'Infoblox systems have a number of options that can be configured to reduce the ability to be exploited in a DoS attack. Primary consideration for this check should be given to client restrictions such as disabling open recursive servers, using ACLs to limit client communication, placement in secure network architecture to prevent address spoofing.

If there is an open recursive DNS service on external name servers, or unrestricted access to internal name servers, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Grid DNS Properties.

Select "Queries" tab.
For external authoritative name servers disable "Allow Recursion" by clearing the check box.
For internal name servers on the "Updates" tab configure either an ACL or ACE for "Allow updates from".
On the "Queries" tab, configure either an ACL or ACE for "Allow queries from".
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15393r295797_chk'
  tag severity: 'medium'
  tag gid: 'V-214178'
  tag rid: 'SV-214178r612370_rule'
  tag stig_id: 'IDNS-7X-000340'
  tag gtitle: 'SRG-APP-000246-DNS-000035'
  tag fix_id: 'F-15391r295798_fix'
  tag 'documentable'
  tag legacy: ['V-68551', 'SV-83041']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
