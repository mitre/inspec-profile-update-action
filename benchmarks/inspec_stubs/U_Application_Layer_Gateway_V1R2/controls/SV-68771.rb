control 'SV-68771' do
  title 'The ALG providing user authentication intermediary services must transmit only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

This requirement applies to ALGs that provide user authentication intermediary services. This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'If the ALG does not provide user authentication intermediary services, this is not applicable.

Verify the ALG transmits only encrypted representations of passwords.

If the ALG does not transmit only encrypted representations of passwords, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure the ALG to transmit only encrypted representations of passwords.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55141r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54525'
  tag rid: 'SV-68771r1_rule'
  tag stig_id: 'SRG-NET-000400-ALG-000097'
  tag gtitle: 'SRG-NET-000400-ALG-000097'
  tag fix_id: 'F-59379r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
