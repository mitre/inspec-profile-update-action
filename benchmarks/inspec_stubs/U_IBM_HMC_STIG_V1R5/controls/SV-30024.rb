control 'SV-30024' do
  title 'The PASSWORD History Count value must be set to 10 or greater.'
  desc 'History Count specifies the number of previous passwords saved for each USERID and compares it with an intended new password. If there is a match with one of the previous passwords, or with the current password, it will reject the intended new password.  The improper setting of any of these fields, individually or in combination with another, can compromise the security of the processing environment.'
  desc 'check', 'Have the System Administrator display the Password Profile Task  window on the Hardware Management Console and validate that the History Count is set to 10.

If the History Count is less than 10, then this is a FINDING.
.'
  desc 'fix', 'Have the System Administrator go into the Password Profile and set the History Count to 10 or greater.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29848r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24356'
  tag rid: 'SV-30024r2_rule'
  tag stig_id: 'HMC0110'
  tag gtitle: 'HMC0110'
  tag fix_id: 'F-26738r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager', 'Systems Programmer']
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
