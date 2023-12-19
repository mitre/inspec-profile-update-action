control 'SV-226916' do
  title 'The portmap or rpcbind service must not be installed unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed.  The portmap or rpcbind services are used by a variety of services using Remote Procedure Calls (RPCs).'
  desc 'check', 'If the system needs the portmap service to operate, this is not applicable.  The rpcbind program is part of a core Solaris package and cannot be removed.  Verify the permissions on the rpcbind file.
# ls -lL /usr/sbin/rpcbind
If the rpcbind service is not required and the rpcbind file has non-zero permissions, this is a finding.'
  desc 'fix', 'Remove all permissions from the rpcbind file.

Procedure:
# chmod 0000 /usr/sbin/rpcbind'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29078r485038_chk'
  tag severity: 'medium'
  tag gid: 'V-226916'
  tag rid: 'SV-226916r603265_rule'
  tag stig_id: 'GEN003815'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29066r485039_fix'
  tag 'documentable'
  tag legacy: ['SV-40810', 'V-22430']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
