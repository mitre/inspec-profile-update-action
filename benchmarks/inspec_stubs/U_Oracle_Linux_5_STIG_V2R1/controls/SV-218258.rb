control 'SV-218258' do
  title 'Root passwords must never be passed over a network in clear text form.'
  desc 'If a user accesses the root account (or any account) using an unencrypted connection, the password is passed over the network in clear text form and is subject to interception and misuse.  This is true even if recommended procedures are followed by logging on to a named account and using the su command to access root.'
  desc 'check', 'Determine if root has logged in over an unencrypted network connection.

Examine /etc/syslog.conf to confirm the location to which "authpriv" messages are being sent.

# grep authpriv.* /etc/syslog.conf

Once the file is determined, perform the following command:

# grep password <file> | more

Look for any lines that do not have sshd as the associated service.

If root has logged in over the network and sshd is not running, this is a finding.'
  desc 'fix', 'Enable SSH on the system and use it for all remote connections used to attain root access'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19733r568702_chk'
  tag severity: 'high'
  tag gid: 'V-218258'
  tag rid: 'SV-218258r603259_rule'
  tag stig_id: 'GEN001100'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-19731r568703_fix'
  tag 'documentable'
  tag legacy: ['V-1046', 'SV-64449']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
