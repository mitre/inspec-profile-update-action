control 'SV-237960' do
  title 'CA VM:Secure product CONFIG file must be restricted to appropriate personnel.'
  desc 'Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Query the CA VM:Secure Product rules.

If there are product rules granting access to the disk on which the product “CONFIG” file resides for system administrators only, this is not a finding.'
  desc 'fix', 'Create rules in the CA VM:Secure product Rules Facility that restricts access to the disk where the product “CONFIG” file resides to system administrators only.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41170r649718_chk'
  tag severity: 'medium'
  tag gid: 'V-237960'
  tag rid: 'SV-237960r649720_rule'
  tag stig_id: 'IBMZ-VM-001250'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-41129r649719_fix'
  tag 'documentable'
  tag legacy: ['SV-93673', 'V-78967']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
