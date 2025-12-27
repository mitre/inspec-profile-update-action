control 'SV-240426' do
  title 'The inetd.conf file, xinetd.conf file, and  xinetd.d directory must be group owned by root, bin, sys, or system.'
  desc "Failure to give ownership of sensitive files or utilities to root provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration, which could weaken the system's security posture."
  desc 'check', 'Check the group-ownership of the "xinetd" configuration files and directories:

# ls -alL /etc/xinetd.conf /etc/xinetd.d

If a file or directory is not group-owned by "root", "bin", "sys", or "system", this is a finding.'
  desc 'fix', 'Change the group-owner of the "xinetd" configuration files and directories:

# chgrp -R root /etc/xinetd.conf /etc/xinetd.d'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43659r671017_chk'
  tag severity: 'medium'
  tag gid: 'V-240426'
  tag rid: 'SV-240426r671019_rule'
  tag stig_id: 'VRAU-SL-000525'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43618r671018_fix'
  tag 'documentable'
  tag legacy: ['SV-100279', 'V-89629']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
