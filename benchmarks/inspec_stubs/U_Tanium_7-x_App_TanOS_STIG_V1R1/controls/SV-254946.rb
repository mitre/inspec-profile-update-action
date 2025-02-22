control 'SV-254946' do
  title 'The SSLCipherSuite must be configured to disable weak encryption algorithms on the Tanium Server.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the server with the tanadmin role.

3. Enter 2: Tanium Operations >> 2: Tanium Configuration Settings >> 1: Edit Tanium Server Settings.

4. Verify the existence of a "SSLCipherSuite" key with a value of:

ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK

If the String "SSLCipherSuite" does not exist with the appropriate list values, this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the server with the tanadmin role.

3. Enter 2: Tanium Operations >> 2: Tanium Configuration Settings >> 1: Edit Tanium Server Settings.

4. Enter the number associated with key "SSLCipherSuite" to edit its value. 

5. Add or modify the "SSLCipherSuite" key to have a value of:

ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58559r867736_chk'
  tag severity: 'medium'
  tag gid: 'V-254946'
  tag rid: 'SV-254946r870383_rule'
  tag stig_id: 'TANS-AP-001095'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-58503r870383_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
