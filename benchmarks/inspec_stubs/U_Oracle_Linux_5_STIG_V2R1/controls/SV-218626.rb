control 'SV-218626' do
  title 'The Network File System (NFS) export configuration file must be group-owned by root, bin, sys, or system.'
  desc "Failure to give group-ownership of the NFS export configuration file to root or a system group provides the designated group-owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of the NFS export configuration file.

Procedure:
# ls -lL /etc/exports

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group ownership of the NFS export configuration file.

Procedure:
# chgrp root /etc/exports'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20101r562858_chk'
  tag severity: 'medium'
  tag gid: 'V-218626'
  tag rid: 'SV-218626r603259_rule'
  tag stig_id: 'GEN005750'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20099r562859_fix'
  tag 'documentable'
  tag legacy: ['V-22492', 'SV-64211']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
