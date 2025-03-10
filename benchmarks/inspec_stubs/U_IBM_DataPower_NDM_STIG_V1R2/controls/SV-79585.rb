control 'SV-79585' do
  title 'If multifactor authentication is not supported and passwords must be used, the DataPower Gateway must enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Search Bar “Administration” >> Access >> RBM Settings >> Password Policy. If Require mixed case is Off, this is a finding.'
  desc 'fix', 'Search Bar “Administration” >> Access >> RBM Settings >> Password Policy. Set Require mixed case to On.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65721r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65095'
  tag rid: 'SV-79585r1_rule'
  tag stig_id: 'WSDP-NM-000055'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-71035r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
