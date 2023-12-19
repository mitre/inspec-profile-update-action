control 'SV-223803' do
  title 'IBM z/OS system administrator must develop a procedure to remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Ask the system administrator for the procedure to remove all software components after updated versions have been installed.

If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a procedure to remove all software components after updated versions have been installed.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25476r515097_chk'
  tag severity: 'medium'
  tag gid: 'V-223803'
  tag rid: 'SV-223803r853628_rule'
  tag stig_id: 'RACF-OS-000490'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-25464r515098_fix'
  tag 'documentable'
  tag legacy: ['V-98313', 'SV-107417']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
