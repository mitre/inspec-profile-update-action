control 'SV-221870' do
  title 'The Oracle Linux operating system must not contain .shosts files.'
  desc 'The .shosts files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', %q(Verify there are no ".shosts" files on the system.

Check the system for the existence of these files with the following command:

# find / -name '*.shosts'

If any ".shosts" files are found on the system, this is a finding.)
  desc 'fix', 'Remove any found ".shosts" files from the system.

# rm /[path]/[to]/[file]/.shosts'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23585r419682_chk'
  tag severity: 'high'
  tag gid: 'V-221870'
  tag rid: 'SV-221870r603260_rule'
  tag stig_id: 'OL07-00-040540'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23574r419683_fix'
  tag 'documentable'
  tag legacy: ['V-99479', 'SV-108583']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
