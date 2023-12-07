control 'WDNS-22-000092_rule' do
  title 'The DNS server implementation must employ strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.'
  desc %q(If unauthorized personnel use maintenance tools, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data.

Nonlocal maintenance and diagnostic activities are conducted by individuals communicating through an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, public key infrastructure (PKI) where certificates are stored on a token protected by a password, passphrase, or biometric.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping", "ls", or "ipconfig" or the hardware and software implementing the monitoring port of an Ethernet switch).

Lack of authentication enables anyone to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. Network access control mechanisms interoperate to prevent unauthorized access and enforce the organization's security policy. Authorization for access to any network element requires an individual account identifier that has been approved, assigned, and configured on an authentication server. Authentication of all administrator accounts for all privilege levels must be accomplished using two or more factors that include the following:

(i) something the user knows (e.g., password/PIN); 
(ii) something the user has (e.g., cryptographic identification device, token); or 
(iii) something the user is (e.g., biometric).)
  desc 'check', "Review the DNS implementation's authentication methods and settings to determine if multifactor authentication is used to gain nonlocal access for maintenance and diagnostics.

If multifactor authentication is not used, this is a finding."
  desc 'fix', 'Configure the DNS system to use multifactor authentication for nonlocal access for maintenance and diagnostics.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000092_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000092'
  tag rid: 'WDNS-22-000092_rule'
  tag stig_id: 'WDNS-22-000092'
  tag gtitle: 'SRG-APP-000185-DNS-000021'
  tag fix_id: 'F-WDNS-22-000092_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
