control 'SV-215213' do
  title 'AIX must employ strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.'
  desc 'If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data.

Some maintenance and test tools are either standalone devices with their own operating systems or are applications bundled with an operating system.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.'
  desc 'check', 'From the command prompt, execute the following to check if "telnetd" is enabled.
# lssrc -t telnet | grep active

If the above command returns output, this is a finding.'
  desc 'fix', 'Disable telnet by executing the following command:
# stopsrc -t telnet'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16411r294090_chk'
  tag severity: 'high'
  tag gid: 'V-215213'
  tag rid: 'SV-215213r877395_rule'
  tag stig_id: 'AIX7-00-001102'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-16409r294091_fix'
  tag 'documentable'
  tag legacy: ['SV-101537', 'V-91439']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
