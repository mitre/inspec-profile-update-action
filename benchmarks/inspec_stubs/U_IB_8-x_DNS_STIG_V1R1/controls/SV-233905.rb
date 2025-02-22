control 'SV-233905' do
  title 'The Infoblox system must employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions.'
  desc %q(If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data. 

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, Public Key Infrastructure (PKI) where certificates are stored on a token protected by a password, passphrase, or biometric.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance but are a part of the system (e.g., the software implementing "ping", "ls", "ipconfig", or the hardware and software implementing the monitoring port of an Ethernet switch).

Lack of authentication enables anyone to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. Network access control mechanisms interoperate to prevent unauthorized access and to enforce the organization's security policy. Authorization for access to any network element requires an individual account identifier that has been approved, assigned, and configured on an authentication server. Authentication of all administrator accounts for all privilege levels must be accomplished using two or more factors that include the following: 

(i) something you know (e.g., password/PIN); 
(ii) something you have (e.g., cryptographic identification device, token); or 
(iii) something you are (e.g., biometric).)
  desc 'check', 'Review the configuration of external authentication methods to verify that multifactor authentication is enabled.  

1. Navigate to Administration >> Administrators >> Authentication Policy. 
2. Ensure multifactor authentication is enabled by validating that the multiple authentication methods are enabled and that the local database is the last entry in the list. 
3. When complete, click "Cancel" to exit the "Properties" screen. 

If the aggregate authentication policy does not provide two or more factors, this is a finding.'
  desc 'fix', 'Note: Refer to the Infoblox Administrator Guide for details on each type of authentication server.  

1. Navigate to Administration >> Authentication Server Groups. 
2. Configure at least one remote authentication group (OCSP, TACACS+, RADIUS, LDAP, or Active Directory).  
3. Navigate to Administration >> Administrators >> Authentication Policy. 
4. Configure the remote authentication source as primary by placing it at the top of the list. 
5. If necessary, move the Local User Database entry to the bottom of the list so it is used last. 
6. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
7. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37090r611235_chk'
  tag severity: 'medium'
  tag gid: 'V-233905'
  tag rid: 'SV-233905r621666_rule'
  tag stig_id: 'IDNS-8X-600001'
  tag gtitle: 'SRG-APP-000185-DNS-000021'
  tag fix_id: 'F-37055r611236_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
