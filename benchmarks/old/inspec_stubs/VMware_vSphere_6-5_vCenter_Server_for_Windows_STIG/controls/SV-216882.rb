control 'SV-216882' do
  title 'The vCenter Server for Windows must restrict access to cryptographic role.'
  desc 'vSphere 6.5 modifies the built-in "Administrator" role to add permission to perform cryptographic operations such as KMS operations and encrypting and decrypting virtual machine disks.  This role must be reserved for cryptographic administrators where VM encryption and/or vSAN encryption is in use.  A new built-in role called "No Cryptography Administrator" has been added to provide all administrative permissions except cryptographic operations. Permissions must be restricted such that normal vSphere administrators are assigned the "No Cryptography Administrator" role or more restrictive. The "Administrator" role must be tightly controlled and must not be applied to administrators who will not be doing cryptographic work. Catastrophic data loss can result from a poorly administered cryptography.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Access Control >> Roles

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-VIPermission | Where {$_.Role -eq "Admin"} | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto

If there are any users other than Solution Users with the "Administrator" role that are not explicitly designated for cryptographic operations, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Access Control >> Roles

Move any accounts not explicitly designated for cryptographic operations, other than Solution Users, to other roles such as "No Cryptography Administrator".'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18113r366360_chk'
  tag severity: 'medium'
  tag gid: 'V-216882'
  tag rid: 'SV-216882r879887_rule'
  tag stig_id: 'VCWN-65-000063'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18111r366361_fix'
  tag 'documentable'
  tag legacy: ['SV-104659', 'V-94829']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
