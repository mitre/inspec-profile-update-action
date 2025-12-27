control 'SV-16844' do
  title 'Virtual machine moved to removable media are not documented.'
  desc 'From a theft perspective, virtual machines are easy to copy and move to a person’s USB drive, portable hard drive, etc. An insider could potentially move the organization’s entire data center on any type of removable media that had sufficient space.'
  desc 'check', 'Ask the IAO/SA if virtual machines have been copied to removable media (DVD, CD-ROM, USB drives).  If so, request the documentation for all virtual machine moves to removable media.  If no documentation exists, this is a finding.'
  desc 'fix', 'Document all virtual machine moves to removable media.'
  impact 0.5
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16262r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15902'
  tag rid: 'SV-16844r1_rule'
  tag stig_id: 'ESX1060'
  tag gtitle: 'Virtual machine moved to removable media not doc'
  tag fix_id: 'F-15863r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
