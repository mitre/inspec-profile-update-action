control 'SV-224016' do
  title 'The IBM z/OS System Administrator must develop a process to notify appropriate personnel when accounts are removed.'
  desc 'When operating system accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual operating system users or for identifying the operating system processes themselves. Sending notification of account disabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes. 

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system Administrator for the documented process to notify appropriate personnel when accounts are removed.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented process to notify appropriate personnel when accounts are removed.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25689r516447_chk'
  tag severity: 'medium'
  tag gid: 'V-224016'
  tag rid: 'SV-224016r561402_rule'
  tag stig_id: 'TSS0-OS-000200'
  tag gtitle: 'SRG-OS-000277-GPOS-00107'
  tag fix_id: 'F-25677r516448_fix'
  tag 'documentable'
  tag legacy: ['SV-107845', 'V-98741']
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
