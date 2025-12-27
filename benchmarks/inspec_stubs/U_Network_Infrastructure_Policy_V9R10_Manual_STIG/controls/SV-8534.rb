control 'SV-8534' do
  title 'External connections to the network must be reviewed and the documentation updated semi-annually.'
  desc 'A network is only as secure as its weakest link. It is imperative that all external connections be reviewed and kept to a minimum needed for operations. All external connections should be treated as untrusted networks. Reviewing who or what the network is connected to empowers the security manager to make sound judgements and security recommendations. Minimizing backdoor circuits and connections reduces the risk for unauthorized access to network resources.'
  desc 'check', 'Review the network topology and interview the ISSO to verify that external connections to the network are reviewed and documented on a semi-annual basis. 

If there are any external connections that have not been documented, or if the connections are not reviewed on a semi-annual basis, this is a finding.'
  desc 'fix', 'Implement a semi-annual review process to document and account for external connections to the organization.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-7429r5_chk'
  tag severity: 'medium'
  tag gid: 'V-8048'
  tag rid: 'SV-8534r4_rule'
  tag stig_id: 'NET0135'
  tag gtitle: 'External connections not documented or reviewed.'
  tag fix_id: 'F-7623r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001121']
  tag nist: ['SC-7 (14)']
end
