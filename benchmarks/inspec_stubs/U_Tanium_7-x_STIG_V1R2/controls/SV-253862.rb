control 'SV-253862' do
  title 'The SSLCipherSuite must be configured to disable weak encryption algorithms on the Tanium Server.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', %q(1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Access the server's registry by typing: "regedit".

4. Click "Enter".

5. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

6. Verify the existence of the string "SSLCipherSuite" with a value of:

ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK

If the string "SSLCipherSuite" does not exist with the appropriate list values, this is a finding.)
  desc 'fix', %q(1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Access the server's registry by typing: regedit <enter>.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

5. Add a new string (REG_SZ) or modify the string "SSLCipherSuite" to have a value of:

ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK)
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57314r842612_chk'
  tag severity: 'medium'
  tag gid: 'V-253862'
  tag rid: 'SV-253862r850365_rule'
  tag stig_id: 'TANS-SV-000044'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-57265r842613_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
