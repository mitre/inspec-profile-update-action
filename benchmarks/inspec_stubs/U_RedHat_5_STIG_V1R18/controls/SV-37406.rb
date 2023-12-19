control 'SV-37406' do
  title 'The inetd.conf file, xinetd.conf file, and the xinetd.d directory must be owned by root or bin.'
  desc "Failure to give ownership of sensitive files or utilities to root provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration possibly weakening the system's security posture."
  desc 'check', 'Check the owner of the xinetd configuration files.

Procedure:
# ls -lL /etc/xinetd.conf 
# ls -laL /etc/xinetd.d
This is a finding if any of the above files or directories are not owned by root or bin.'
  desc 'fix', 'Change the owner of the xinetd configuration files.
# chown root /etc/xinetd.conf /etc/xinetd.d/*'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36089r1_chk'
  tag severity: 'medium'
  tag gid: 'V-821'
  tag rid: 'SV-37406r1_rule'
  tag stig_id: 'GEN003720'
  tag gtitle: 'GEN003720'
  tag fix_id: 'F-31336r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
