control 'SV-37940' do
  title 'The Network File System (NFS) export configuration file must be group-owned by root, bin, sys, or system.'
  desc "Failure to give group-ownership of the NFS export configuration file to root or a system group provides the designated group-owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the group ownership of the NFS export configuration file.

Procedure:
# chgrp root /etc/exports'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22492'
  tag rid: 'SV-37940r1_rule'
  tag stig_id: 'GEN005750'
  tag gtitle: 'GEN005750'
  tag fix_id: 'F-32431r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
