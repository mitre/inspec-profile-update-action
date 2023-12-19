control 'SV-237942' do
  title 'The CA VM:Secure LOGONBY command must be restricted to system administrators.'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.

The LOGONBY statement designates up to eight user IDs that can use their own passwords to log on to and use the virtual machine.'
  desc 'check', 'Examine the CA VM:Secure Rules facility for "LOGONBY" rules.

If the "LOGONBY" rules specifies users that are not system administrators, this is a finding.'
  desc 'fix', 'Assure that any "LOGONBY" rules in the CA VM: Secure Rules Facility only specifies users who are system administrators.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41152r859009_chk'
  tag severity: 'medium'
  tag gid: 'V-237942'
  tag rid: 'SV-237942r859011_rule'
  tag stig_id: 'IBMZ-VM-000990'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-41111r859010_fix'
  tag 'documentable'
  tag legacy: ['SV-93637', 'V-78931']
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']
end
