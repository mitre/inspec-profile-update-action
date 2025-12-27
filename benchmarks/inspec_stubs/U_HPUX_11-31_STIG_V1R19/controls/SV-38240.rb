control 'SV-38240' do
  title 'Root passwords must never be passed over a network in clear text form.'
  desc 'If a user accesses the root account (or any account) using an unencrypted connection, the password is passed over the network in clear text form and is subject to interception and misuse.  This is true even if recommended procedures are followed by logging on to a named account and using the su command to access root.'
  desc 'check', 'Perform the following to determine if root has logged in over an unencrypted network connection. The first command determines if root has logged in over a network. The second will check to see if the SSH daemon is running.

Procedure:
# last -R | grep "^root " | egrep -v "reboot|console" | more
# ps -ef |grep sshd

If the output from the last command shows root has logged in over the network and sshd is not running, this is a finding.'
  desc 'fix', 'Enable SSH on the system and use it for all remote connections used to attain root access.'
  impact 0.7
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36280r1_chk'
  tag severity: 'high'
  tag gid: 'V-1046'
  tag rid: 'SV-38240r1_rule'
  tag stig_id: 'GEN001100'
  tag gtitle: 'GEN001100'
  tag fix_id: 'F-31537r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
