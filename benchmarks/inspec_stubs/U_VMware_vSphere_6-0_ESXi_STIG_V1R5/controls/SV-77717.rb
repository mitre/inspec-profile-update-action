control 'SV-77717' do
  title 'The system must remove keys from the SSH authorized_keys file.'
  desc %q(ESXi hosts come with SSH which can be enabled to allow remote access without requiring user authentication.  To enable password free access copy the remote users public key into the "/etc/ssh/keys-root/authorized_keys" file on the ESXi host.  The presence of the remote user's public key in the "authorized_keys" file identifies the user as trusted, meaning the user is granted access to the host without providing a password.  If using Lockdown Mode and SSH is disabled then login with authorized keys will have the same restrictions as username/password.)
  desc 'check', 'Log in to the host and verify the /etc/ssh/keys-root/authorized_keys file does not exist or is empty (zero bytes): 
# ls -la /etc/ssh/keys-root/authorized_keys

or

#cat /etc/ssh/keys-root/authorized_keys

If the authorized_keys file exists and is not empty, this is a finding.'
  desc 'fix', 'As root, log in to the host and zero/remove /etc/ssh/keys-root/authorized_keys file: 
# >/etc/ssh/keys-root/authorized_keys
or
# rm /etc/ssh/keys-root/authorized_keys'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63961r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63227'
  tag rid: 'SV-77717r1_rule'
  tag stig_id: 'ESXI-06-000029'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69145r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
