control 'SV-81553' do
  title 'The SSLCipherSuite must be configured to disable weak encryption algorithms on the Tanium Server.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', %q(Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Access the server's registry by typing: "regedit". Enter.

Navigate to HKLM >> Software >> Wow6432Node >> Tanium >> Tanium Server.

Verify the existence of a String "SSLCipherSuite" with a value of:

AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-CCM:AES1 28-CCM:AES256-CCM8:AES128-CCM8:AES256-SHA256:AES128-SHA256:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA

If the String "SSLCipherSuite" does not exist with the appropriate list values, this is a finding.)
  desc 'fix', %q(Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Access the server's registry by typing: regedit <enter>

Navigate to HKLM >> Software >> Wow6432Node >> Tanium >> Tanium Server.


Add or modify the String "SSLCipherSuite" to have a value of:

AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-CCM:AES1 28-CCM:AES256-CCM8:AES128-CCM8:AES256-SHA256:AES128-SHA256:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA)
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67699r2_chk'
  tag severity: 'medium'
  tag gid: 'V-67063'
  tag rid: 'SV-81553r2_rule'
  tag stig_id: 'TANS-SV-000044'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-73163r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
