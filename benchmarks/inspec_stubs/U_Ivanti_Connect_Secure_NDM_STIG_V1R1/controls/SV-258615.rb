control 'SV-258615' do
  title 'The ICS must be configured to transmit only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

This is applicable to the account of last resort which uses a password. Secure password while in transit for admin access.'
  desc 'check', 'In the ICS Web UI, navigate to System >> Configuration >> Inbound SSL Options.

Under "Allowed SSL and TLS Version", if "Accept only TLS 1.2 (maximize security)" is checked.

Navigate to System >> Configuration >> Outbound SSL Options.

Under "Allowed SSL and TLS Version", if "Accept only TLS 1.2 (maximize security)" is checked.

If the ICS does not transmit only encrypted representations of passwords, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to System >> Configuration >> Inbound SSL Options.
1. Under "Allowed SSL and TLS Version", check the box for "Accept only TLS 1.2 (maximize security)".
2. Click "Save Changes".
3. Click "Proceed" for acceptance of Cipher Change.

Navigate to System >> Configuration >> Outbound SSL Options.
1. Under "Allowed SSL and TLS Version", check the box for "Accept only TLS 1.2 (maximize security)".
2. Click "Save Changes".
3. Click "Proceed" for acceptance of Cipher Change.'
  impact 0.7
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62355r930531_chk'
  tag severity: 'high'
  tag gid: 'V-258615'
  tag rid: 'SV-258615r930533_rule'
  tag stig_id: 'IVCS-NM-000450'
  tag gtitle: 'SRG-APP-000172-NDM-000259'
  tag fix_id: 'F-62264r930532_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
