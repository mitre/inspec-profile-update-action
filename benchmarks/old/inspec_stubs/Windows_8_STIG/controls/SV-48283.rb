control 'SV-48283' do
  title 'Policy must require that system administrators (SAs) be trained for the operating systems used by systems under their control.'
  desc 'If system administrators (SAs) are assigned to systems running operating systems for which they have no training, these systems are at additional risk of unintentional misconfiguration that may result in vulnerabilities or decreased availability of the system.'
  desc 'check', 'Review the list of SAs assigned to each system and compare this information to SA training records. If SAs are assigned to systems running operating systems for which there is no record of training, this is a finding.'
  desc 'fix', 'Establish site policy that requires SAs be trained for all operating systems running on systems under their control.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44961r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36666'
  tag rid: 'SV-48283r2_rule'
  tag stig_id: 'WN08-00-000014'
  tag gtitle: 'WIN00-000014'
  tag fix_id: 'F-41418r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
