control 'SV-209025' do
  title 'All GIDs referenced in /etc/passwd must be defined in /etc/group.'
  desc 'Inconsistency in GIDs between /etc/passwd and /etc/group could lead to a user having unintended rights.'
  desc 'check', "To ensure all GIDs referenced in /etc/passwd are defined in /etc/group, run the following command: 

# pwck -r | grep 'no group'

There should be no output. 
If there is output, this is a finding."
  desc 'fix', 'Add a group to the system for each GID referenced without a corresponding group.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9278r357860_chk'
  tag severity: 'low'
  tag gid: 'V-209025'
  tag rid: 'SV-209025r793746_rule'
  tag stig_id: 'OL6-00-000294'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9278r357861_fix'
  tag 'documentable'
  tag legacy: ['V-50973', 'SV-65179']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
