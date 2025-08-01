control 'SV-38861' do
  title 'The kernel core dump data directory must be owned by root.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  As the system memory may contain sensitive information, it must be protected accordingly. If the kernel core dump data directory is not owned by root, the core dumps contained in the directory may be subject to unauthorized access.'
  desc 'check', 'Determine the core file copy location.
#sysdumpdev -l | grep -i "core dir"
  
Check the ownership of the kernel core dump data directory.
# ls -ld < dump file location >
If the kernel core dump data directory is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the kernel core dump data directory to root. 

# chown root /var/adm/ras

Supplementary Information:   The location of the kernel dump area should be moved out of /var/adm/ras.  This directory may be world read/writeable.   A suggestion would be to create /var/adm/kcore;  chown root:sys /var/adm/kcore; chmod 700 /var/adm/kcore.   
Change where the system copies  its kernel core files to.
sysdumpdev -d /var/adm/kcore'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37854r3_chk'
  tag severity: 'low'
  tag gid: 'V-11997'
  tag rid: 'SV-38861r1_rule'
  tag stig_id: 'GEN003520'
  tag gtitle: 'GEN003520'
  tag fix_id: 'F-33116r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
