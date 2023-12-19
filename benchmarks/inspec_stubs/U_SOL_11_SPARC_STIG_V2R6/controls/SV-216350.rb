control 'SV-216350' do
  title 'The nobody access for RPC encryption key storage service must be disabled.'
  desc 'If login by the user "nobody" is allowed for secure RPC, there is an increased risk of system compromise. If keyserv holds a private key for the "nobody" user, it will be used by key_encryptsession to compute a magic phrase which can be easily recovered by a malicious user.'
  desc 'check', %q(Determine if the rpc-authdes package is installed:

# pkg list solaris/legacy/security/rpc-authdes

If the output of this command is:

pkg list: no packages matching 'solaris/legacy/security/rpc-authdes' installed

no further action is required.

Determine if "nobody" access for keyserv is enabled.

# grep "^ENABLE_NOBODY_KEYS=" /etc/default/keyserv 

If the output of the command is not:

ENABLE_NOBODY_KEYS=NO

this is a finding.)
  desc 'fix', "Determine if the rpc-authdes package is installed:

# pkg list solaris/legacy/security/rpc-authdes

If the output of this command is:

pkg list: no packages matching 'solaris/legacy/security/rpc-authdes' installed

no further action is required.

The root role is required.

Modify the /etc/default/keyserv file.

# pfedit /etc/default/keyserv

Locate the line:

#ENABLE_NOBODY_KEYS=YES

Change it to:

ENABLE_NOBODY_KEYS=NO"
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17586r462487_chk'
  tag severity: 'medium'
  tag gid: 'V-216350'
  tag rid: 'SV-216350r603267_rule'
  tag stig_id: 'SOL-11.1-040320'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17584r462488_fix'
  tag 'documentable'
  tag legacy: ['SV-60961', 'V-48089']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
