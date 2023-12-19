control 'SV-227786' do
  title 'Kernel core dumps must be disabled unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  Kernel core dumps may consume a considerable amount of disk space and may result in Denial of Service by exhausting the available space on the target file system.  The kernel core dump process may increase the amount of time a system is unavailable due to a crash.  Kernel core dumps can be useful for kernel debugging.'
  desc 'check', "Verify savecore is not used.
# dumpadm | grep 'Savecore enabled'
If the value is true, this is a finding.

OR

# grep DUMPADM_ENABLE /etc/dumpadm.conf
If the value is yes, this is a finding."
  desc 'fix', 'Disable savecore.
# dumpadm -n'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29948r489712_chk'
  tag severity: 'medium'
  tag gid: 'V-227786'
  tag rid: 'SV-227786r603266_rule'
  tag stig_id: 'GEN003510'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29936r489713_fix'
  tag 'documentable'
  tag legacy: ['V-22404', 'SV-26605']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
