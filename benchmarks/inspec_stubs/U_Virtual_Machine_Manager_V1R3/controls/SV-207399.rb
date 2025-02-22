control 'SV-207399' do
  title 'The VMM must employ strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.'
  desc 'If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive VMM information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data.

Some maintenance and test tools are either standalone devices with their own VMMs or are applications bundled with a VMM.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the VMM or VMM component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.'
  desc 'check', 'Verify the VMM employs strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to employ strong authenticators in the establishment of nonlocal maintenance and diagnostic sessions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7656r365607_chk'
  tag severity: 'medium'
  tag gid: 'V-207399'
  tag rid: 'SV-207399r378958_rule'
  tag stig_id: 'SRG-OS-000125-VMM-000630'
  tag gtitle: 'SRG-OS-000125'
  tag fix_id: 'F-7656r365608_fix'
  tag 'documentable'
  tag legacy: ['SV-71259', 'V-56999']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
