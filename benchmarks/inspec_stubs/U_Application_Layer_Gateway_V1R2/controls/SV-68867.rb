control 'SV-68867' do
  title 'The ALG must generate unique session identifiers using a FIPS 140-2 approved random number generator.'
  desc "Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

This requirement is applicable to ALGs that create and use sessions and session identifiers to control user communications. If an attacker can guess the session identifier, or can inject or manually insert session information, the valid user's application session can be compromised."
  desc 'check', 'Verify the ALG generates unique session identifiers using a FIPS 140-2 approved random number generator.

If the ALG does not generate unique session identifiers using a FIPS 140-2 approved random number generator, this is a finding.'
  desc 'fix', 'Configure ALG to generate unique session identifiers using a FIPS 140-2 approved random number generator.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55241r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54621'
  tag rid: 'SV-68867r1_rule'
  tag stig_id: 'SRG-NET-000234-ALG-000116'
  tag gtitle: 'SRG-NET-000234-ALG-000116'
  tag fix_id: 'F-59477r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
