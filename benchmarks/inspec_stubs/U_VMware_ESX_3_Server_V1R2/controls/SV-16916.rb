control 'SV-16916' do
  title 'ESX Server assets are not configured with the correct posture in VMS.'
  desc 'Correctly configuring the ESX Server asset in VMS will ensure that the appropriate vulnerabilities are assigned to the asset. If the asset is not configured with the correct posture, vulnerabilities may be open on the asset.  These open vulnerabilities may allow an attacker to access the system.'
  desc 'check', 'If check ESX0863 is a finding, this should be marked a finding also.

If the assets are registered, verify that the following postures are registered.  If any of the postures are not registered, this is a finding.   

ESX Server 3
Tomcat 5.x'
  desc 'fix', 'Register ESX Servers in VMS with the correct posture.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16605r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15974'
  tag rid: 'SV-16916r1_rule'
  tag stig_id: 'ESX0866'
  tag gtitle: 'ESX0866'
  tag fix_id: 'F-15973r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'VIVM-1'
end
