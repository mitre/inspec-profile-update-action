control 'SV-226337' do
  title 'The default permissions of global system objects must be increased.'
  desc 'Windows systems maintain a global list of shared system resources such as DOS device names, mutexes, and semaphores.  Each type of object is created with a default DACL that specifies who can access the objects with what permissions.  If this policy is enabled, the default DACL is stronger, allowing nonadministrative users to read shared objects, but not modify shared objects that they did not create.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Session Manager\\

Value Name: ProtectionMode

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28039r476855_chk'
  tag severity: 'low'
  tag gid: 'V-226337'
  tag rid: 'SV-226337r794682_rule'
  tag stig_id: 'WN12-SO-000076'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-28027r476856_fix'
  tag 'documentable'
  tag legacy: ['SV-52877', 'V-1173']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
