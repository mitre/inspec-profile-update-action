control 'SV-37181' do
  title 'The system must not have special privilege accounts, such as shutdown and halt.'
  desc 'If special privilege accounts are compromised, the accounts could provide privileges to execute malicious commands on a system.'
  desc 'fix', 'Remove any special privilege accounts, such as shutdown and halt, from the /etc/passwd and /etc/shadow files using the "userdel" or "system-config-users" commands.'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag severity: 'high'
  tag gid: 'V-4268'
  tag rid: 'SV-37181r1_rule'
  tag stig_id: 'GEN000000-LNX00320'
  tag gtitle: 'GEN000000-LNX00320'
  tag fix_id: 'F-31139r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000225', 'CCI-000764']
  tag nist: ['AC-6', 'IA-2']
end
