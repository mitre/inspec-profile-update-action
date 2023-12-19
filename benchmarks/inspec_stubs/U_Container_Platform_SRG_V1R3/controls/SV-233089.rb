control 'SV-233089' do
  title 'The container platform must prohibit password reuse for a minimum of 10 generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

To meet password policy requirements, passwords need to be changed at specific policy-based intervals.

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the result is a password that is not changed as per policy requirements.

The references for this check are:
NIST SP 800-53 :: IA-5 (1) (e)
NIST SP 800-53A :: IA-5 (1).1 (v)
NIST SP 800-53 Revision 4 :: IA-5 (1)
CNSS 1253'
  desc 'check', 'Review the container platform configuration to determine if it prohibits password reuse for a minimum of five generations. 

If the container platform does not prohibit password reuse for a minimum of five generations, this is a finding.'
  desc 'fix', 'Configure the container platform to prohibit password reuse for a minimum of five generations.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36025r600754_chk'
  tag severity: 'medium'
  tag gid: 'V-233089'
  tag rid: 'SV-233089r600756_rule'
  tag stig_id: 'SRG-APP-000165-CTR-000405'
  tag gtitle: 'SRG-APP-000165'
  tag fix_id: 'F-35993r600755_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
