control 'SV-234110' do
  title 'The SSLCipherSuite must be configured to disable weak encryption algorithms on the Tanium Server.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', %q(Access the Tanium Server interactively.

Log on to the server with an account that has administrative privileges.

Access the server's registry by typing: "regedit".

Click "Enter".

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Verify the existence of a String "SSLCipherSuite" with a value of:

ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK

If the String "SSLCipherSuite" does not exist with the appropriate list values, this is a finding.)
  desc 'fix', %q(Access the Tanium Server interactively.

Log on to the server with an account that has administrative privileges.

Access the server's registry by typing: regedit <enter>.

Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

Add or modify the String "SSLCipherSuite" to have a value of:

ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK)
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37295r610830_chk'
  tag severity: 'medium'
  tag gid: 'V-234110'
  tag rid: 'SV-234110r612749_rule'
  tag stig_id: 'TANS-SV-000044'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-37260r610831_fix'
  tag 'documentable'
  tag legacy: ['SV-102293', 'V-92191']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
