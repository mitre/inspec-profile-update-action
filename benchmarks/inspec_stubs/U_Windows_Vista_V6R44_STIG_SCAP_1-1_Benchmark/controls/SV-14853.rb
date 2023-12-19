control 'SV-14853' do
  title 'User Account Control - Non UAC Compliant Application Virtualization'
  desc 'This check verifies that non UAC compliant applications will run in virtualized file and registry entries allowing them to run.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Virtualize file and registry write failures to per-user locations” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14242'
  tag rid: 'SV-14853r1_rule'
  tag gtitle: 'UAC - Non UAC Compliant Application Virtualization'
  tag fix_id: 'F-28848r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
