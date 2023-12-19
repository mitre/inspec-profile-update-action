control 'SV-252939' do
  title 'There must be no ".shosts" files on The TOSS operating system.'
  desc 'The ."shosts" files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', %q(Verify there are no ."shosts" files on TOSS with the following command:

$ sudo find / -name '*.shosts'

If any ."shosts" files are found, this is a finding.)
  desc 'fix', 'Remove any found ."shosts" files from the system.

$ sudo rm /[path]/[to]/[file]/.shosts'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56392r824139_chk'
  tag severity: 'medium'
  tag gid: 'V-252939'
  tag rid: 'SV-252939r824141_rule'
  tag stig_id: 'TOSS-04-010370'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56342r824140_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
