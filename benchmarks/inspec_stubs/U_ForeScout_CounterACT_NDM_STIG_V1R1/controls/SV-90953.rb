control 'SV-90953' do
  title 'If multifactor authentication is not supported and passwords must be used, CounterACT must enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Some devices may not have the need to provide a group authenticator; this is considered a matter of device design. In those instances where the device design includes the use of a group authenticator, this requirement will apply. This requirement applies to accounts created and managed on or by the network device.'
  desc 'check', 'Determine if CounterACT requires at least one lower-case character to be used in passwords. This requirement may be verified by demonstration or configuration review.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Verify the "password must contain at least # lower case alphabetic characters" radio button is selected and configured to at least 1.

If CounterACT does not enforce at least one lower-case character, this is a finding.'
  desc 'fix', 'Configure CounterACT to require a minimum of one lower-case character.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Ensure the "password must contain at least # lower case alphabetic characters" radio button is selected and configured to at least 1.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76265'
  tag rid: 'SV-90953r1_rule'
  tag stig_id: 'CACT-NM-000148'
  tag gtitle: 'SRG-APP-000167-NDM-000255'
  tag fix_id: 'F-82901r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
