control 'SV-44654' do
  title 'The system must not have special privilege accounts, such as shutdown and halt.'
  desc 'If special privilege accounts are compromised, the accounts could provide privileges to execute malicious commands on a system.'
  desc 'check', 'Perform the following to check for unnecessary privileged accounts:

# grep "^shutdown" /etc/passwd
# grep "^halt" /etc/passwd
# grep "^reboot" /etc/passwd

If any unnecessary privileged accounts exist this is a finding.'
  desc 'fix', 'Remove any special privilege accounts, such as shutdown and halt, from the /etc/passwd and /etc/shadow files using the "userdel" or "system-config-users" commands.'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42158r1_chk'
  tag severity: 'high'
  tag gid: 'V-4268'
  tag rid: 'SV-44654r1_rule'
  tag stig_id: 'GEN000000-LNX00320'
  tag gtitle: 'GEN000000-LNX00320'
  tag fix_id: 'F-38109r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000764']
  tag nist: ['AC-6', 'IA-2']
end
