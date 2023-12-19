control 'SV-70981' do
  title 'The operating system must remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Verify the operating system removes all software components after updated versions have been installed. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to remove all software components after updated versions have been installed.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57291r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56721'
  tag rid: 'SV-70981r1_rule'
  tag stig_id: 'SRG-OS-000437-GPOS-00194'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-61617r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
