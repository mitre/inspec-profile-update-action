control 'SV-243118' do
  title 'The vCenter Server must restrict access to the cryptographic role.'
  desc %q(In vSphere 6.7, the built-in "Administrator" role contains permission to perform cryptographic operations such as KMS functions and encrypting and decrypting virtual machine disks. This role must be reserved for cryptographic administrators where VM encryption and/or vSAN encryption is in use. 

A new built-in role called "No Cryptography Administrator" exists to provide all administrative permissions except cryptographic operations. Permissions must be restricted such that normal vSphere administrators are assigned the 'No Cryptography Administrator' role or more restrictive. 

The "Administrator" role must be tightly controlled and must not be applied to administrators who will not be doing cryptographic work. Catastrophic data loss can result from poorly administered cryptography.)
  desc 'check', 'From the vSphere Client, go to Administration >> Access Control >> Roles.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VIPermission | Where {$_.Role -eq "Admin"} | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto

If there are any users other than Solution Users with the "Administrator" role that are not explicitly designated for cryptographic operations, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Access Control >> Roles.

Move any accounts not explicitly designated for cryptographic operations, other than Solution Users, to other roles such as "No Cryptography Administrator".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46393r719595_chk'
  tag severity: 'medium'
  tag gid: 'V-243118'
  tag rid: 'SV-243118r719597_rule'
  tag stig_id: 'VCTR-67-000063'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46350r719596_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
