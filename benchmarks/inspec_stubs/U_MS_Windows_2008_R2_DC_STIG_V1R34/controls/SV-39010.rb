control 'SV-39010' do
  title 'Anonymous access to the root DSE of a non-public directory must be disabled.'
  desc 'Allowing anonymous access to the root DSE data on a directory server provides potential attackers with a number of details about the configuration and data contents of a directory. For example, the namingContexts attribute indicates the directory space contained in the directory; the supportedLDAPVersion attribute indicates which versions of the LDAP protocol the server supports; and the supportedSASLMechanisms attribute indicates the names of supported authentication mechanisms. An attacker with this information may be able to select more precisely targeted attack tools or higher value targets.'
  desc 'check', %q(At this time, this is a finding for all Windows domain controllers for sensitive or classified levels as Windows Active Directory Domain Services (AD DS) does not provide a method to restrict anonymous access to the root DSE on domain controllers.

The following can be used to verify anonymous access if allowed.

Open a command prompt (not elevated).
Run "ldp.exe".
From the Connection menu, select Bind.
Select Simple bind for the Bind type.
Clear the User, Password, and Domain fields, Click OK.

RootDSE attributes should display, such as various namingContexts.

Confirmation of anonymous access will be displayed at the end:
res = ldap_simple_bind_s
Authenticated as: 'NT AUTHORITY\ANONYMOUS LOGON')
  desc 'fix', 'Implement network protections to reduce the risk of anonymous access.

Network hardware ports at the site are subject to 802.1x authentication or MAC address restrictions. 

Premise firewall or host restrictions prevent access to ports 389, 636, 3268, and 3269 from client hosts not explicitly identified by domain (.mil) or IP address.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-46917r1_chk'
  tag severity: 'low'
  tag gid: 'V-14797'
  tag rid: 'SV-39010r2_rule'
  tag stig_id: 'DS00.3131_2008_R2'
  tag gtitle: 'Anonymous Access to Non-Public Root DSE Data'
  tag fix_id: 'F-45047r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'The following network controls allow the finding severity to be downgraded to not a finding since these measures lower the risk associated with anonymous access.

Network hardware ports at the site are subject to 802.1x authentication or MAC address restrictions. 

Premise firewall or host restrictions prevent access to ports 389, 636, 3268, and 3269 from client hosts not explicitly identified by domain (.mil) or IP address.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
