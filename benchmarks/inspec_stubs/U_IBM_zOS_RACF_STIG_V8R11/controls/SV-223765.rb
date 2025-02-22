control 'SV-223765' do
  title 'The IBM z/OS System Administrator (SA) must develop a process to notify appropriate personnel when accounts are removed.'
  desc 'When operating system accounts are removed, user accessibility is affected. Accounts are utilized for identifying individual operating system users or for identifying the operating system processes themselves. Sending notification of account removal events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.'
  desc 'check', 'Ask the system Administrator for the documented process to notify appropriate personnel when accounts are removed.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented develop a process to notify appropriate personnel when accounts are removed.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25438r514983_chk'
  tag severity: 'medium'
  tag gid: 'V-223765'
  tag rid: 'SV-223765r604139_rule'
  tag stig_id: 'RACF-OS-000090'
  tag gtitle: 'SRG-OS-000277-GPOS-00107'
  tag fix_id: 'F-25426r514984_fix'
  tag 'documentable'
  tag legacy: ['V-98237', 'SV-107341']
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
