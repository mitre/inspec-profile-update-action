control 'SV-227626' do
  title 'The NIS/NIS+/yp command files must have mode 0755 or less permissive.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Unauthorized modification of these files could compromise these processes and the system."
  desc 'check', "Perform the following to check NIS file mode.
# ls -lRa /usr/lib/netsvc/yp /var/yp
If the file's mode is more permissive than 0755, this is a finding."
  desc 'fix', 'Change the mode of NIS/NIS+/yp command files to 0755 or less permissive.

Procedure:
# chmod -R 0755 /usr/lib/netsvc/yp /var/yp'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29788r488438_chk'
  tag severity: 'medium'
  tag gid: 'V-227626'
  tag rid: 'SV-227626r603266_rule'
  tag stig_id: 'GEN001360'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29776r488439_fix'
  tag 'documentable'
  tag legacy: ['V-791', 'SV-27175']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
