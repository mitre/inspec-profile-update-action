control 'SV-203653' do
  title 'The operating system must employ strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.'
  desc 'If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data.

Some maintenance and test tools are either standalone devices with their own operating systems or are applications bundled with an operating system.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.'
  desc 'check', 'Verify the operating system employs strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to employ strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.'
  impact 0.7
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3778r557204_chk'
  tag severity: 'high'
  tag gid: 'V-203653'
  tag rid: 'SV-203653r877395_rule'
  tag stig_id: 'SRG-OS-000125-GPOS-00065'
  tag gtitle: 'SRG-OS-000125'
  tag fix_id: 'F-3778r557205_fix'
  tag 'documentable'
  tag legacy: ['SV-71071', 'V-56811']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
