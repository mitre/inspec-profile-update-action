control 'SV-234984' do
  title 'There must be no .shosts files on the SUSE operating system.'
  desc 'The .shosts files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', %q(Text: Verify there are no ".shosts" files on the SUSE operating system.

Check the system for the existence of these files with the following command:

> sudo find / \( -path /.snapshots -o -path /sys -o -path /proc \\) -prune -o -name '.shosts' -print

If any ".shosts" files are found on the system, this is a finding.)
  desc 'fix', 'Remove any ".shosts" files found on the SUSE operating system.

> sudo rm /[path]/[to]/[file]/.shosts'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38172r619221_chk'
  tag severity: 'high'
  tag gid: 'V-234984'
  tag rid: 'SV-234984r622137_rule'
  tag stig_id: 'SLES-15-040020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38135r619222_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
