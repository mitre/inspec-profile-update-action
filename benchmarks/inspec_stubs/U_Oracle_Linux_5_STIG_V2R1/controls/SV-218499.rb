control 'SV-218499' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19974r562630_chk'
  tag severity: 'medium'
  tag gid: 'V-218499'
  tag rid: 'SV-218499r603259_rule'
  tag stig_id: 'GEN003720'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19972r562631_fix'
  tag 'documentable'
  tag legacy: ['V-821', 'SV-64233']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
