control 'SV-923' do
  title 'The system must be checked for extraneous device files at least weekly.'
  desc 'If an unauthorized device is allowed to exist on the system, there is the possibility the system may perform unauthorized operations.'
  desc 'check', 'Check the system for an automated job, or check with the SA, to determine if the system is checked for extraneous device files on a weekly basis. If no automated or manual process is in place, this is a finding.'
  desc 'fix', 'Establish a weekly automated or manual process to create a list of device files on the system and determine if any files have been added, moved, or deleted since the last list was generated.  

Generate a list of device files.
# find / -type b -o -type c > device-file-list'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-464r2_chk'
  tag severity: 'low'
  tag gid: 'V-923'
  tag rid: 'SV-923r2_rule'
  tag stig_id: 'GEN002260'
  tag gtitle: 'GEN002260'
  tag fix_id: 'F-1077r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000318']
  tag nist: ['CM-3 f']
end
