control 'SV-226500' do
  title 'The NIS/NIS+/yp command files must have mode 0755 or less permissive.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Unauthorized modification of these files could compromise these processes and the system."
  desc 'check', "Perform the following to check NIS file mode.
# ls -lRa /usr/lib/netsvc/yp /var/yp
If the file's mode is more permissive than 0755, this is a finding."
  desc 'fix', 'Change the mode of NIS/NIS+/yp command files to 0755 or less permissive.

Procedure:
# chmod -R 0755 /usr/lib/netsvc/yp /var/yp'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28661r482888_chk'
  tag severity: 'medium'
  tag gid: 'V-226500'
  tag rid: 'SV-226500r854411_rule'
  tag stig_id: 'GEN001360'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-28649r482889_fix'
  tag 'documentable'
  tag legacy: ['SV-27175', 'V-791']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
