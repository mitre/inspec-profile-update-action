control 'SV-100277' do
  title 'The xinetd.conf file, and the xinetd.d directory must be owned by root or bin.'
  desc "Failure to give ownership of sensitive files or utilities to root provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration, which could weaken the system's security posture."
  desc 'check', 'Check the owner of the "xinetd" configuration files:

# ls -lL /etc/xinetd.conf 
# ls -laL /etc/xinetd.d

This is a finding if any of the above files or directories are not owned by "root" or "bin".'
  desc 'fix', 'Change the owner of the "xinetd" configuration files:

# chown root /etc/xinetd.conf /etc/xinetd.d/*'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89319r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89627'
  tag rid: 'SV-100277r1_rule'
  tag stig_id: 'VRAU-SL-000520'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96369r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
