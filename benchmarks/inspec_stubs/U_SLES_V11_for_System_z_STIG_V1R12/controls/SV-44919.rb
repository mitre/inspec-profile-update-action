control 'SV-44919' do
  title 'Root passwords must never be passed over a network in clear text form.'
  desc 'If a user accesses the root account (or any account) using an unencrypted connection, the password is passed over the network in clear text form and is subject to interception and misuse.  This is true even if recommended procedures are followed by logging on to a named account and using the su command to access root.'
  desc 'check', 'Determine if root has logged in over an unencrypted network connection.

First determine if root has logged in over a network.
Procedure:
# last | grep "^root " | egrep -v "reboot| |ttyS0" | more

If root has logged in over the network, this is a finding.'
  desc 'fix', 'Enable SSH on the system and authenticate with a userid/password that has “su” privileges to attain root access.'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42360r1_chk'
  tag severity: 'high'
  tag gid: 'V-1046'
  tag rid: 'SV-44919r1_rule'
  tag stig_id: 'GEN001100'
  tag gtitle: 'GEN001100'
  tag fix_id: 'F-38351r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
