control 'SV-253859' do
  title 'The SSLHonorCipherOrder must be configured to disable weak encryption algorithms on the Tanium Server.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', %q(1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Access the server's registry by typing: regedit <enter>.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

5. Verify the existence of a DWORD "SSLHonorCipherOrder" with a value of "0x00000001" (hex).

If the DWORD "SSLHonorCipherOrder" does not exist with a value of "0x00000001" (hex), this is a finding.)
  desc 'fix', %q(1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Access the server's registry by typing: regedit <enter>.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

5. Add or modify the DWORD "SSLHonorCipherOrder" to have a value of 0x00000001 (hex).)
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57311r842603_chk'
  tag severity: 'medium'
  tag gid: 'V-253859'
  tag rid: 'SV-253859r850365_rule'
  tag stig_id: 'TANS-SV-000035'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-57262r842604_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
