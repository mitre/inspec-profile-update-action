control 'SV-79581' do
  title 'The DataPower Gateway must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Search Bar “Administration” >> Access >> RBM Settings >> Password Policy. If Minimum length is Off, this is a finding'
  desc 'fix', 'Search Bar “Administration” >> Access >> RBM Settings >> Password Policy. Set Minimum length to at least 15'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65717r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65091'
  tag rid: 'SV-79581r1_rule'
  tag stig_id: 'WSDP-NM-000053'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-71031r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
