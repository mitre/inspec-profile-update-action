control 'SV-35206' do
  title "The system's access control program must log each system’s access attempt."
  desc 'If access attempts are not logged, then multiple attempts to log on to the system by an unauthorized user may go undetected.'
  desc 'fix', 'Configure the access restriction program to log every access attempt. Ensure the implementation instructions for TCP_WRAPPERS are followed so logging of system access attempts is logged into the system log files. If an alternate application is used, it must support this function.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-941'
  tag rid: 'SV-35206r2_rule'
  tag stig_id: 'GEN006600'
  tag gtitle: 'GEN006600'
  tag fix_id: 'F-32112r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-2, ECAR-1, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
