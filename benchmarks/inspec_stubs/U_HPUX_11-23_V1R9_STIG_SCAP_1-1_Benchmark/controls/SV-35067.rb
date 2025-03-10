control 'SV-35067' do
  title 'The inetd.conf file, xinetd.conf file, and the xinetd.d directory must be owned by root or bin.'
  desc "Failure to give ownership of sensitive files or utilities to root provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the ownership of the inetd.conf file to root or bin. 
# chown root <file or directory>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-821'
  tag rid: 'SV-35067r1_rule'
  tag stig_id: 'GEN003720'
  tag gtitle: 'GEN003720'
  tag fix_id: 'F-30239r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
