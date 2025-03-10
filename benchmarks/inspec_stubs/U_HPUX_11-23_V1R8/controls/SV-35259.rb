control 'SV-35259' do
  title 'Kernel core dumps must be disabled unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash.  Kernel core dumps may consume a considerable amount of disk space and may result in Denial of Service by exhausting the available space on the target file system.  The kernel core dump process may increase the amount of time a system is unavailable due to a crash.  Kernel core dumps can be useful for kernel debugging.'
  desc 'check', %q(Verify crash dumps are disabled.
# crashconf -v 

If the included list is not empty or fully disabled, this is a finding.

Alternatively,
# crashconf -v | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[  \t]*//'  | cut -f 3,3 -d " " | \
egrep -c -i "yes,"

If the above command returns a value >0, this is a finding.)
  desc 'fix', 'Disable crash dumps.
# crashconf -e all

Additionally, edit /etc/rc.config.d/crashconf and:

•	set CRASH_EXCLUDED_PAGES="all"
•	set CRASHCONF_ENABLED="0"'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35095r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22404'
  tag rid: 'SV-35259r1_rule'
  tag stig_id: 'GEN003510'
  tag gtitle: 'GEN003510'
  tag fix_id: 'F-30364r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
