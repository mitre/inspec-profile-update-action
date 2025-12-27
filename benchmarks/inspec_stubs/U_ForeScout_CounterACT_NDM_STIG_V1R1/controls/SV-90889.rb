control 'SV-90889' do
  title 'CounterACT must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

To meet password policy requirements, passwords need to be changed at specific policy-based intervals.

If the network device allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Determine if CounterACT prohibits password reuse for a minimum of five generations. This requirement may be verified by demonstration or configuration review.

1. Verify if the user profiles are using external authentication server or local. If using local, proceed to Step 2. If using external, verify the settings using the Authentication Server configuration guide.
2. Log on to the CounterACT Administrator UI.
3. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
4. Verify the "Last" radio button is selected and the option with "5" passwords cannot be reused is configured.

If CounterACT does not prohibit password reuse for a minimum of five generations, this is a finding.'
  desc 'fix', 'Configure CounterACT to prohibit password reuse for a minimum of five generations.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Ensure the "Last" radio button is selected and the option with "5" passwords cannot be reused is configured.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75887r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76201'
  tag rid: 'SV-90889r1_rule'
  tag stig_id: 'CACT-NM-000031'
  tag gtitle: 'SRG-APP-000165-NDM-000253'
  tag fix_id: 'F-82839r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
