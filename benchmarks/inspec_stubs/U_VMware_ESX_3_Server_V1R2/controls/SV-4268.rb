control 'SV-4268' do
  title 'The system must not have special privilege accounts, such as shutdown and halt.'
  desc 'If special privilege accounts are compromised, the accounts could provide privileges to execute malicious commands on a system.'
  desc 'check', 'Perform the following to check for unnecessary privileged accounts:

	# more /etc/passwd

Some examples of unnecessary privileged accounts include halt, shutdown, reboot and who.'
  desc 'fix', 'Remove any special privilege accounts, such as shutdown and halt, from the /etc/passwd and /etc/shadow files.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2089r2_chk'
  tag severity: 'high'
  tag gid: 'V-4268'
  tag rid: 'SV-4268r2_rule'
  tag stig_id: 'GEN000000-LNX00320'
  tag gtitle: 'GEN000000-LNX00320'
  tag fix_id: 'F-4179r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000225', 'CCI-000764']
  tag nist: ['AC-6', 'IA-2']
end
