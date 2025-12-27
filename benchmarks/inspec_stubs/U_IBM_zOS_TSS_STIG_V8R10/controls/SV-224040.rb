control 'SV-224040' do
  title 'IBM z/OS system administrator must develop a procedure to remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Ask the system administrator for the procedure to remove all software components after updated versions have been installed.

If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a procedure to remove all software components after updated versions have been installed.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25713r516519_chk'
  tag severity: 'medium'
  tag gid: 'V-224040'
  tag rid: 'SV-224040r877878_rule'
  tag stig_id: 'TSS0-OS-000450'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-25701r516520_fix'
  tag 'documentable'
  tag legacy: ['SV-107891', 'V-98787']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
