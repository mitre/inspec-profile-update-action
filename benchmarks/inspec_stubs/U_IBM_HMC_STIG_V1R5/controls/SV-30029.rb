control 'SV-30029' do
  title 'The terminal or workstation must lock out after a maximum of 15 minutes of inactivity, requiring the account password to resume.'
  desc 'If the system, workstation, or terminal does not lock the session after more than15 minutes of inactivity, requiring a password to resume operations, the system or individual data could be compromised by an alert intruder who could exploit the oversight.'
  desc 'check', 'Have the System Administrator display the User Properties window on the Hardware Management Console and check that the timeout minutes are set to a maximum of 15.

If the Verify Timeout minutes are set to more than 15, then this is a FINDING.'
  desc 'fix', 'The System Administrator will display the User Properties window and will ensure that the Verify timeout minutes are set to a maximum of 15.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29864r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24361'
  tag rid: 'SV-30029r2_rule'
  tag stig_id: 'HMC0150'
  tag gtitle: 'HMC0150'
  tag fix_id: 'F-26748r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'PESL-1'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
