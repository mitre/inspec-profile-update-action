control 'SV-251408' do
  title 'The Ivanti MobileIron Core server must prohibit password reuse for a minimum of four generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

To meet password policy requirements, passwords need to be changed at specific policy-based intervals.

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.

'
  desc 'check', 'Verify Core is configured to enforce password history reuse of four last passwords:

1. Log in to the Core console.
2. Security >> Password Policy.
3. Verify  "Enforce Password History (Last 4 passwords)" is enabled.

 If "Enforce Password History (Last 4 passwords)" is not enabled, this is a finding.'
  desc 'fix', 'Configure Core to enforce password history reuse of four last passwords:

1. Log in to the Core console.
2. Security >> Password Policy.
3. Check "Enable" for "Enforce Password History (Last 4 passwords)".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54843r806354_chk'
  tag severity: 'medium'
  tag gid: 'V-251408'
  tag rid: 'SV-251408r806356_rule'
  tag stig_id: 'IMIC-11-004950'
  tag gtitle: 'SRG-APP-000165-UEM-000095'
  tag fix_id: 'F-54796r809565_fix'
  tag satisfies: ['FMT_SMF.1(2)b \nReference: PP-MDM-431025']
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
