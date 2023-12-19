control 'SV-226907' do
  title 'The inetd.conf file must be owned by root or bin.'
  desc "Failure to give ownership of sensitive files or utilities to root provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of inetd.conf file.

Procedure:
# ls -lL /etc/inet/inetd.conf

This is a finding if any of the above files or directories are not owned by root or bin.'
  desc 'fix', 'Change the ownership of the inetd.conf file to root or bin.

Procedure:
# chown root /etc/inet/inetd.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29069r485008_chk'
  tag severity: 'medium'
  tag gid: 'V-226907'
  tag rid: 'SV-226907r854429_rule'
  tag stig_id: 'GEN003720'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29057r485009_fix'
  tag 'documentable'
  tag legacy: ['V-821', 'SV-39883']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
