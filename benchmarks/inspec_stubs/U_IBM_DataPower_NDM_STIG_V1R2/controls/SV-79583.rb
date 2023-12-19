control 'SV-79583' do
  title 'The DataPower Gateway must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the network device allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Search Bar “Administration” >> Access >> RBM Settings >> Password Policy. If Control reuse is Off, this is a finding.'
  desc 'fix', 'Search Bar “Administration” >> Access >> RBM Settings >> Password Policy. Set Control reuse to On, set Reuse history to at least 5.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65719r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65093'
  tag rid: 'SV-79583r1_rule'
  tag stig_id: 'WSDP-NM-000054'
  tag gtitle: 'SRG-APP-000165-NDM-000253'
  tag fix_id: 'F-71033r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
