control 'SV-226912' do
  title 'The services file must be group-owned by root, bin, or sys.'
  desc "Failure to give ownership of system configuration files to root or a system group provides the designated owner and unauthorized users with the potential to change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of the services file.

Procedure:
# ls -lL /etc/services

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group-owner of the services file.

Procedure:
# chgrp root /etc/services'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29074r485023_chk'
  tag severity: 'medium'
  tag gid: 'V-226912'
  tag rid: 'SV-226912r603265_rule'
  tag stig_id: 'GEN003770'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29062r485024_fix'
  tag 'documentable'
  tag legacy: ['V-22427', 'SV-39903']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
