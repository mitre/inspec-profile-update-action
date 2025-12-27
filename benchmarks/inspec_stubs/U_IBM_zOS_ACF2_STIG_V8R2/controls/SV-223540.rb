control 'SV-223540' do
  title 'IBM z/OS system administrator must develop a process notify appropriate personnel when accounts are removed.'
  desc 'When operating system accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual operating system users or for identifying the operating system processes themselves. Sending notification of account disabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes. 

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Ask the system Administrator for the documented process to notify appropriate personnel when accounts are removed.

If there is no documented process this is a finding.'
  desc 'fix', 'Develop a documented process to notify appropriate personnel when accounts are removed.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25213r500755_chk'
  tag severity: 'medium'
  tag gid: 'V-223540'
  tag rid: 'SV-223540r533198_rule'
  tag stig_id: 'ACF2-OS-000040'
  tag gtitle: 'SRG-OS-000277-GPOS-00107'
  tag fix_id: 'F-25201r500756_fix'
  tag 'documentable'
  tag legacy: ['V-97785', 'SV-106889']
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
