control 'SV-79587' do
  title 'If multifactor authentication is not supported and passwords must be used, the DataPower Gateway must enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Search Bar “Administration” >> Access >> RBM Settings >> Password Policy. If Require mixed case is Off, this is a finding.'
  desc 'fix', 'Search Bar “Administration” >> Access >> RBM Settings >> Password Policy. Set Require mixed case to On.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65723r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65097'
  tag rid: 'SV-79587r1_rule'
  tag stig_id: 'WSDP-NM-000056'
  tag gtitle: 'SRG-APP-000167-NDM-000255'
  tag fix_id: 'F-71037r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
