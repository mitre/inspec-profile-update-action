control 'SV-45176' do
  title 'The system must be checked for extraneous device files at least weekly.'
  desc 'If an unauthorized device is allowed to exist on the system, there is the possibility the system may perform unauthorized operations.'
  desc 'check', 'Check the system for an automated job, or check with the SA, to determine if the system is checked for extraneous device files on a weekly basis. If no automated or manual process is in place, this is a finding.'
  desc 'fix', 'Establish a weekly automated or manual process to create a list of device files on the system and determine if any files have been added, moved, or deleted since the last list was generated. A list of device files can be generated with this command:
# find / -type b -o -type c > device-file-list'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42521r1_chk'
  tag severity: 'low'
  tag gid: 'V-923'
  tag rid: 'SV-45176r1_rule'
  tag stig_id: 'GEN002260'
  tag gtitle: 'GEN002260'
  tag fix_id: 'F-38574r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000318']
  tag nist: ['CM-3 f']
end
