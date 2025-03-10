control 'SV-81601' do
  title 'The SSLHonorCipherOrder DWORD  must be configured to disable weak encryption algorithms on the Tanium Server.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', %q(Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Access the server's registry by typing: regedit <enter>

Navigate to HKLM >> Software >> Wow6432Node >> Tanium >> Tanium Server.

Verify the existence of a DWORD "SSLHonorCipherOrder" with a value of "0x00000001" (hex).

If the DWORD "SSLHonorCipherOrder" does not exist with a value of "0x00000001" (hex), this is a finding.)
  desc 'fix', %q(Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Access the server's registry by typing: regedit <enter>

Navigate to HKLM >> Software >> Wow6432Node >> Tanium >> Tanium Server.

Add or modify the DWORD "SSLHonorCipherOrder" to have a value of 0x00000001 (hex).)
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67747r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67111'
  tag rid: 'SV-81601r2_rule'
  tag stig_id: 'TANS-SV-000035'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-73211r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
