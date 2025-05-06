control 'SV-254295' do
  title 'Windows Server 2022 must, at a minimum, offload audit records of interconnected systems in real time and offload standalone or nondomain-joined systems weekly.'
  desc 'Protection of log data includes assuring the log data is not accidentally lost or deleted. Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  desc 'check', 'Verify the audit records, at a minimum, are offloaded for interconnected systems in real time and offloaded for standalone or nondomain-joined systems weekly. 

If they are not, this is a finding.'
  desc 'fix', 'Configure the system to, at a minimum, offload audit records of interconnected systems in real time and offload standalone or nondomain-joined systems weekly.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57780r848699_chk'
  tag severity: 'medium'
  tag gid: 'V-254295'
  tag rid: 'SV-254295r848701_rule'
  tag stig_id: 'WN22-AU-000020'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-57731r848700_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
