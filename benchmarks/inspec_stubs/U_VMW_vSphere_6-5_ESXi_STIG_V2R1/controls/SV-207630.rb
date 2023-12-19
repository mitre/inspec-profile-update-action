control 'SV-207630' do
  title 'The ESXi host must remove keys from the SSH authorized_keys file.'
  desc %q(ESXi hosts come with SSH which can be enabled to allow remote access without requiring user authentication.  To enable password free access copy the remote users public key into the "/etc/ssh/keys-root/authorized_keys" file on the ESXi host.  The presence of the remote user's public key in the "authorized_keys" file identifies the user as trusted, meaning the user is granted access to the host without providing a password.  If using Lockdown Mode and SSH is disabled then login with authorized keys will have the same restrictions as username/password.)
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# ls -la /etc/ssh/keys-root/authorized_keys

or

# cat /etc/ssh/keys-root/authorized_keys

If the authorized_keys file exists and is not empty, this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, zero or remove the /etc/ssh/keys-root/authorized_keys file:

# >/etc/ssh/keys-root/authorized_keys

or

# rm /etc/ssh/keys-root/authorized_keys'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7885r364289_chk'
  tag severity: 'medium'
  tag gid: 'V-207630'
  tag rid: 'SV-207630r388482_rule'
  tag stig_id: 'ESXI-65-000029'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7885r364290_fix'
  tag 'documentable'
  tag legacy: ['V-94005', 'SV-104091']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
