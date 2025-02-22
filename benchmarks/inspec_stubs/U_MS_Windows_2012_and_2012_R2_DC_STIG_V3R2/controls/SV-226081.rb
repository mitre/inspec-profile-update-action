control 'SV-226081' do
  title 'Anonymous access to the root DSE of a non-public directory must be disabled.'
  desc 'Allowing anonymous access to the root DSE data on a directory server provides potential attackers with a number of details about the configuration and data contents of a directory.  For example, the namingContexts attribute indicates the directory space contained in the directory; the supportedLDAPVersion attribute indicates which versions of the LDAP protocol the server supports; and the supportedSASLMechanisms attribute indicates the names of supported authentication mechanisms.  An attacker with this information may be able to select more precisely targeted attack tools or higher value targets.'
  desc 'check', %q(At this time, this is a finding for all Windows domain controllers for sensitive or classified levels as Windows Active Directory Domain Services (AD DS) does not provide a method to restrict anonymous access to the root DSE on domain controllers.

The following can be used to verify anonymous access is allowed.

Open a command prompt (not elevated).
Run "ldp.exe".
From the Connection menu, select Bind.
Clear the User, Password, and Domain fields.
Select Simple bind for the Bind type, Click OK.

RootDSE attributes should display, such as various namingContexts.

Confirmation of anonymous access will be displayed at the end:
res = ldap_simple_bind_s
Authenticated as: 'NT AUTHORITY\ANONYMOUS LOGON')
  desc 'fix', 'Implement network protections to reduce the risk of anonymous access.

Network hardware ports at the site are subject to 802.1x authentication or MAC address restrictions. 

Premise firewall or host restrictions prevent access to ports 389, 636, 3268, and 3269 from client hosts not explicitly identified by domain (.mil) or IP address.

Severity Override Guidance: The following network controls allow the finding severity to be downgraded to not a finding since these measures lower the risk associated with anonymous access.'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27783r475566_chk'
  tag severity: 'low'
  tag gid: 'V-226081'
  tag rid: 'SV-226081r569184_rule'
  tag stig_id: 'WN12-AD-000012-DC'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27771r641840_fix'
  tag 'documentable'
  tag legacy: ['SV-51186', 'V-14797']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
