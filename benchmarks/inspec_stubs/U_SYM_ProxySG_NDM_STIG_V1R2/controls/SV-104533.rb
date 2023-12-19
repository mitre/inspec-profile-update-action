control 'SV-104533' do
  title 'Symantec ProxySG must transmit only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Network devices can accomplish this by making direct function calls to encryption modules or by leveraging operating system encryption capabilities.'
  desc 'check', 'Verify only TLS management services are enabled.

1. Log on to the Web Management Console.
2. Click Configuration >> Services >> Management Services.
3. Ensure that "HTTP-Console" is not enabled and that "HTTPS-Console" is enabled.

If Symantec ProxySG does not transmit only encrypted representations of passwords, this is a finding.'
  desc 'fix', 'Enable TLS management services.

1. Log on to the Web Management Console.
2. Click Configuration >> Services >> Management Services.
3. Ensure "HTTPS-Console" is already enabled.
4. Ensure "HTTP-Console" is not enabled.
5. Click "Apply".'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93893r1_chk'
  tag severity: 'high'
  tag gid: 'V-94703'
  tag rid: 'SV-104533r1_rule'
  tag stig_id: 'SYMP-NM-000260'
  tag gtitle: 'SRG-APP-000172-NDM-000259'
  tag fix_id: 'F-100821r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
