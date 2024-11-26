control 'SV-223581' do
  title 'IBM z/OS system administrator must develop a procedure to remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Ask the system administrator for the procedure to remove all software components after updated versions have been installed.

If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a procedure to remove all software components after updated versions have been installed.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25254r500878_chk'
  tag severity: 'medium'
  tag gid: 'V-223581'
  tag rid: 'SV-223581r533198_rule'
  tag stig_id: 'ACF2-OS-002420'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-25242r500879_fix'
  tag 'documentable'
  tag legacy: ['V-97867', 'SV-106971']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
