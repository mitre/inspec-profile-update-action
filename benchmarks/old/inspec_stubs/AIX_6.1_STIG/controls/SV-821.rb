control 'SV-821' do
  title 'The inetd.conf file, xinetd.conf file, and the xinetd.d directory must be owned by root or bin.'
  desc "Failure to give ownership of sensitive files or utilities to root provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of inetd.conf file.

Procedure:
# ls -lL /etc/inetd.conf

This is a finding if any of the above files or directories are not owned by root or bin.'
  desc 'fix', 'Change the ownership of the inetd.conf file to root or bin.  

Procedure:
# chown root /etc/inetd.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-567r2_chk'
  tag severity: 'medium'
  tag gid: 'V-821'
  tag rid: 'SV-821r2_rule'
  tag stig_id: 'GEN003720'
  tag gtitle: 'GEN003720'
  tag fix_id: 'F-975r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
