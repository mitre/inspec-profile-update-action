control 'SV-240494' do
  title 'System executables must have restrictive permissions.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Verify that that system executables are not group-writable or world writable with the following command:

ls -l /bin /sbin /usr/bin /usr/libexec /usr/local/bin /usr/local/sbin /usr/sbin

If any  files are group-writable or world writable, this is a finding.'
  desc 'fix', 'For any file that was a finding:

sudo chmod go-w <filename>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43727r671221_chk'
  tag severity: 'medium'
  tag gid: 'V-240494'
  tag rid: 'SV-240494r671223_rule'
  tag stig_id: 'VRAU-SL-000922'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-43686r671222_fix'
  tag 'documentable'
  tag legacy: ['SV-100415', 'V-89765']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
