control 'SV-37150' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35865r2_chk'
  tag severity: 'high'
  tag gid: 'V-1046'
  tag rid: 'SV-37150r2_rule'
  tag stig_id: 'GEN001100'
  tag gtitle: 'GEN001100'
  tag fix_id: 'F-31120r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
