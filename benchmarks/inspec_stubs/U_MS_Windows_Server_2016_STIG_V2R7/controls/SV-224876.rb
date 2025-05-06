control 'SV-224876' do
  title 'Windows Server 2016 must, at a minimum, offload audit records of interconnected systems in real time and offload standalone or nondomain-joined systems weekly.'
  desc 'Protection of log data includes ensuring the log data is not accidentally lost or deleted. Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  desc 'check', 'Verify the audit records, at a minimum, are offloaded for interconnected systems in real time and offloaded for standalone or nondomain-joined systems weekly. 

If they are not, this is a finding.'
  desc 'fix', 'Configure the system to, at a minimum, offload audit records of interconnected systems in real time and offload standalone or nondomain-joined systems weekly.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26567r857247_chk'
  tag severity: 'medium'
  tag gid: 'V-224876'
  tag rid: 'SV-224876r860019_rule'
  tag stig_id: 'WN16-AU-000020'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-26555r857248_fix'
  tag 'documentable'
  tag legacy: ['SV-88055', 'V-73403']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
