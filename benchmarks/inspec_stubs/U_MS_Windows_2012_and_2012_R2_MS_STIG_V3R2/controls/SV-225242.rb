control 'SV-225242' do
  title 'Policy must require that system administrators (SAs) be trained for the operating systems used by systems under their control.'
  desc 'If SAs are assigned to systems running operating systems for which they have no training, these systems are at additional risk of unintentional misconfiguration that may result in vulnerabilities or decreased availability of the system.'
  desc 'check', 'Determine whether the site has a policy that requires SAs be trained for all operating systems running on systems under their control.  If  the site does not have a policy requiring SAs be trained for all operating systems under their control, this is a finding.'
  desc 'fix', 'Establish site policy that requires SAs be trained for all operating systems running on systems under their control.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-26941r471068_chk'
  tag severity: 'medium'
  tag gid: 'V-225242'
  tag rid: 'SV-225242r569185_rule'
  tag stig_id: 'WN12-00-000006'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26929r471069_fix'
  tag 'documentable'
  tag legacy: ['SV-51577', 'V-36666']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
