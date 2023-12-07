control 'SV-34574' do
  title 'The system must not have the unnecessary "news" account.'
  desc 'Accounts that provide no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'fix', 'Remove the "news" account from the /etc/passwd file before connecting a system to the network.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-27275'
  tag rid: 'SV-34574r1_rule'
  tag stig_id: 'GEN000290-2'
  tag gtitle: 'GEN000290-2'
  tag fix_id: 'F-33038r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000012']
  tag nist: ['AC-2 j']
end
