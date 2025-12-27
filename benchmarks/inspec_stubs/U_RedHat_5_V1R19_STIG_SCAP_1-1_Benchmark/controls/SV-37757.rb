control 'SV-37757' do
  title "The system's access control program must log each system access attempt."
  desc 'If access attempts are not logged, then multiple attempts to log on to the system by an unauthorized user may go undetected.'
  desc 'fix', 'Configure the access restriction program to log every access attempt. Ensure the implementation instructions for tcp_wrappers are followed so system access attempts are recorded to the system log files. If an alternate application is used, it must support this function.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-941'
  tag rid: 'SV-37757r3_rule'
  tag stig_id: 'GEN006600'
  tag gtitle: 'GEN006600'
  tag fix_id: 'F-32219r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
