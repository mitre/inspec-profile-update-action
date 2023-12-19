control 'SV-239166' do
  title 'The Photon operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled on the command line.'
  desc 'When the Ctrl-Alt-Del target is enabled, a locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of systems availability due to unintentional reboot.'
  desc 'check', 'At the command line, execute the following command:

# systemctl status ctrl-alt-del.target

Expected result:

ctrl-alt-del.target
Loaded: masked (/dev/null; bad)
Active: inactive (dead)

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, execute the following command:

# systemctl mask ctrl-alt-del.target'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42377r675304_chk'
  tag severity: 'medium'
  tag gid: 'V-239166'
  tag rid: 'SV-239166r675306_rule'
  tag stig_id: 'PHTN-67-000095'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42336r675305_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
