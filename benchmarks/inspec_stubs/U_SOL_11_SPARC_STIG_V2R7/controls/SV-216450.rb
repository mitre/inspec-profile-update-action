control 'SV-216450' do
  title 'Kernel core dumps must be disabled unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system. The kernel core dump process may increase the amount of time a system is unavailable due to a crash. Kernel core dumps can be useful for kernel debugging.'
  desc 'check', %q(The root role is required.
This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.


Verify savecore is not used.

# dumpadm | grep 'Savecore enabled' 

If the value is yes, this is a finding.)
  desc 'fix', 'The root role is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Disable savecore.

# dumpadm -n'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17686r371438_chk'
  tag severity: 'medium'
  tag gid: 'V-216450'
  tag rid: 'SV-216450r603267_rule'
  tag stig_id: 'SOL-11.1-080080'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17684r371439_fix'
  tag 'documentable'
  tag legacy: ['SV-60885', 'V-48013']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
