control 'SV-100355' do
  title 'All GIDs referenced in /etc/passwd must be defined in /etc/group.'
  desc 'Inconsistency in GIDs between /etc/passwd and /etc/group could lead to a user having unintended rights.'
  desc 'check', 'To ensure all GIDs referenced in /etc/passwd are defined in /etc/group, run the following command:  

# pwck -rq

If a line is returned, this is a finding.'
  desc 'fix', 'Add a group to the system for each GID referenced without a corresponding group.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89397r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89705'
  tag rid: 'SV-100355r1_rule'
  tag stig_id: 'VRAU-SL-000740'
  tag gtitle: 'SRG-OS-000121-GPOS-00062'
  tag fix_id: 'F-96447r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
