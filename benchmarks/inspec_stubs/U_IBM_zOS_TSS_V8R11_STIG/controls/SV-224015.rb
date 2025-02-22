control 'SV-224015' do
  title 'The IBM z/OS System Administrator must develop a process to notify appropriate personnel when accounts are deleted.'
  desc 'When operating system accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual operating system users or for identifying the operating system processes themselves. Sending notification of account disabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes. 

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system Administrator for the documented process to notify appropriate personnel when accounts are deleted.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented process to notify appropriate personnel when accounts are deleted.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25688r516444_chk'
  tag severity: 'medium'
  tag gid: 'V-224015'
  tag rid: 'SV-224015r877855_rule'
  tag stig_id: 'TSS0-OS-000190'
  tag gtitle: 'SRG-OS-000276-GPOS-00106'
  tag fix_id: 'F-25676r516445_fix'
  tag 'documentable'
  tag legacy: ['V-98739', 'SV-107843']
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
