control 'SV-104539' do
  title 'The Symantec ProxySG Web Management Console and SSH sessions must implement cryptographic mechanisms to protect the confidentiality of nonlocal maintenance and diagnostic communications.'
  desc 'This requirement requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Verify only AES ciphers are used for nonlocal maintenance and diagnostic communications.

1. Log on to the CLI via SSH.
2. Type "enable", enter the enable password.
3. Type "configure terminal", press "Enter".
4. Type "show management services" and confirm that the Cipher Suite parameter contains only ciphers that use AES.

If Web Management Console and SSH sessions does not implement cryptographic mechanisms to protect the confidentiality of nonlocal maintenance and diagnostic communications, this is a finding.'
  desc 'fix', 'Configure the Symantec ProxySG to use only AES ciphers for nonlocal maintenance and diagnostic communications.

1. Log on to the CLI via SSH.
2. Type "enable", enter the enable password.
3. Type "configure terminal" and press "Enter".
4. Type "management-services" and press "Enter", type "edit HTTPS-Console" and press "Enter".
5. Type "view" to display the list of configured cipher suites.
6. Type "attribute cipher-suite" followed by a space-delimited list of only cipher suites from step 5 containing AES and press "Enter".'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93899r1_chk'
  tag severity: 'high'
  tag gid: 'V-94709'
  tag rid: 'SV-104539r1_rule'
  tag stig_id: 'SYMP-NM-000290'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-100827r1_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
