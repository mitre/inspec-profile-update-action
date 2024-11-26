control 'SV-254945' do
  title 'The SSLHonorCipherOrder must be configured to disable weak encryption algorithms on the Tanium Server.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the server with the tanadmin role.

3. Enter 2: Tanium Operations >> 2: Tanium Configuration Settings >> 1: Edit Tanium Server Settings.

4. Verify the existence of a "SSLHonorCipherOrder" key with a value of "1".

If the "SSLHonorCipherOrder" key does not exist with a value of "1", this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the server with the tanadmin role.

3. Enter 2: Tanium Operations >> 2: Tanium Configuration Settings >> 1: Edit Tanium Server Settings.

4. Enter number associated with key "SSLHonorCipherOrder" to edit its value. 

5. Add or modify the "SSLHonorCipherOrder" key to have a value of "1".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58558r867733_chk'
  tag severity: 'medium'
  tag gid: 'V-254945'
  tag rid: 'SV-254945r870382_rule'
  tag stig_id: 'TANS-AP-001090'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-58502r870382_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
