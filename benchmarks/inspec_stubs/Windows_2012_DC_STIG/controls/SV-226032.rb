control 'SV-226032' do
  title 'Policy must require that system administrators (SAs) be trained for the operating systems used by systems under their control.'
  desc 'If SAs are assigned to systems running operating systems for which they have no training, these systems are at additional risk of unintentional misconfiguration that may result in vulnerabilities or decreased availability of the system.'
  desc 'check', 'Determine whether the site has a policy that requires SAs be trained for all operating systems running on systems under their control.  If  the site does not have a policy requiring SAs be trained for all operating systems under their control, this is a finding.'
  desc 'fix', 'Establish site policy that requires SAs be trained for all operating systems running on systems under their control.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27734r475419_chk'
  tag severity: 'medium'
  tag gid: 'V-226032'
  tag rid: 'SV-226032r794371_rule'
  tag stig_id: 'WN12-00-000006'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27722r475420_fix'
  tag 'documentable'
  tag legacy: ['SV-51577', 'V-36666']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
