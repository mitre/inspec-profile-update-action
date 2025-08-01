control 'SV-205175' do
  title 'The DNS server implementation must employ strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.'
  desc %q(If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data. 

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).

Lack of authentication enables anyone to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. Network access control mechanisms interoperate to prevent unauthorized access and to enforce the organization's security policy. Authorization for access to any network element requires an individual account identifier that has been approved, assigned, and configured on an authentication server. Authentication of all administrator accounts for all privilege levels must be accomplished using two or more factors that include the following:

(i) something you know (e.g., password/PIN); 
(ii) something you have (e.g., cryptographic identification device, token); or 
(iii) something you are (e.g., biometric).)
  desc 'check', "Review the DNS implementation's authentication methods and settings to determine if multifactor authentication is utilized to gain nonlocal access for maintenance and diagnostics. 

If multifactor authentication is not utilized, this is a finding."
  desc 'fix', 'Configure the DNS system to utilize multifactor authentication for nonlocal access for maintenance and diagnostics.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5442r392441_chk'
  tag severity: 'medium'
  tag gid: 'V-205175'
  tag rid: 'SV-205175r879620_rule'
  tag stig_id: 'SRG-APP-000185-DNS-000021'
  tag gtitle: 'SRG-APP-000185'
  tag fix_id: 'F-5442r392442_fix'
  tag 'documentable'
  tag legacy: ['SV-69059', 'V-54813']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
