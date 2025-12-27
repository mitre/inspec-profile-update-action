control 'SV-223542' do
  title 'IBM z/OS system administrator must develop a process notify appropriate personnel when accounts are deleted.'
  desc 'When operating system accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual operating system users or for identifying the operating system processes themselves. Sending notification of account disabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes. 

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Develop a documented develop a process to notify appropriate personnel when accounts are deleted.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented process to notify appropriate personnel when accounts are deleted.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25215r500761_chk'
  tag severity: 'medium'
  tag gid: 'V-223542'
  tag rid: 'SV-223542r533198_rule'
  tag stig_id: 'ACF2-OS-000060'
  tag gtitle: 'SRG-OS-000276-GPOS-00106'
  tag fix_id: 'F-25203r500762_fix'
  tag 'documentable'
  tag legacy: ['SV-106893', 'V-97789']
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
