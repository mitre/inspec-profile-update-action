control 'SV-77465' do
  title 'Riverbed Optimization System (RiOS) must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the network device allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify that RiOS is configured to prohibit password reuse for a minimum of five generations.

Navigate to the device Management Console
Navigate to Configure >> Security >> Password Policy

Verify that "Minimum Interval for Password Reuse:" is set to "5"

If "Minimum Interval for Password Reuse:" is not set to "5", this is a finding.'
  desc 'fix', 'Configure RiOS to prohibit password reuse for a minimum of five generations.

Navigate to the device Management Console
Navigate to Configure >> Security >> Password Policy

Set the value of "Minimum Interval for Password Reuse:" to "5"

Click "Apply"
Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63727r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62975'
  tag rid: 'SV-77465r1_rule'
  tag stig_id: 'RICX-DM-000124'
  tag gtitle: 'SRG-APP-000165-NDM-000253'
  tag fix_id: 'F-68893r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
