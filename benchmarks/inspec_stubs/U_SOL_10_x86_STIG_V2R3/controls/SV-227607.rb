control 'SV-227607' do
  title 'The root shell must be located in the / file system.'
  desc 'To ensure the root shell is available in repair and administrative modes, the root shell must be located in the / file system.'
  desc 'check', %q(Perform the following to determine if /usr is partitioned.
# grep /usr /etc/vfstab 

If /usr is partitioned, check the location of root's default shell.  
# awk -F: '$1 == "root" {print $7}' /etc/passwd
If the root shell is found to be on a partitioned /usr filesystem or is in a directory symlinked to a partitioned /usr filesystem, even if the actual root shell is a symlink back to the root filesystem, this is a finding.)
  desc 'fix', "Change the root account's shell to one present on the / filesystem. Example: 

# usermod -s /sbin/sh root"
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29769r488378_chk'
  tag severity: 'low'
  tag gid: 'V-227607'
  tag rid: 'SV-227607r603266_rule'
  tag stig_id: 'GEN001080'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29757r488379_fix'
  tag 'documentable'
  tag legacy: ['V-1062', 'SV-27157']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
