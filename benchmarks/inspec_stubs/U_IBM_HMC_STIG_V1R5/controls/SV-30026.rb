control 'SV-30026' do
  title 'The PASSWORD expiration day(s) value must be set to equal or less then 60 days.'
  desc "Expiration Day(s) specifies the maximum number of days that each user's password is valid. When a user logs on to the Hardware Management Console it compares the system password interval value specified in the user profile and it uses the lower of the two values to determine if the user's, password has expired. The improper setting of any of these fields, individually or in combination with another, can compromise the security of the processing environment."
  desc 'check', 'Have the System Administrator display the Password Profile Task  window on the Hardware Management Console and validate that the Expiration day(s) is set to equal or less  then 60 days.

If the Expiration day(s) is set to equal or less then 60 days, this is not a FINDING.

If the Expiration day(s) is greater than 60 days, then this is a FINDING.'
  desc 'fix', 'Have the System Administrator go into the Password Profile and set the Expiration day(s) to equal or less then 60 days.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29852r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24358'
  tag rid: 'SV-30026r2_rule'
  tag stig_id: 'HMC0120'
  tag gtitle: 'HMC0120'
  tag fix_id: 'F-26739r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager', 'Systems Programmer']
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
