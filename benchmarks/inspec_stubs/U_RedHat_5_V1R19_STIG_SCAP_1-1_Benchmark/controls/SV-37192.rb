control 'SV-37192' do
  title 'All run control scripts must have mode 0755 or less permissive.'
  desc 'If the startup files are writable by other users, they could modify the startup files to insert malicious commands into the startup files.'
  desc 'fix', 'Ensure all system startup files have mode 0755 or less permissive. Examine the "rc" files, and all files in the rc1.d (rc2.d, and so on) directories, and in the /etc/init.d directory to ensure they are not world-writable. If they are world-writable, use the chmod command to correct the vulnerability and research why they are world-writable.

Procedure: 
# chmod 755 <startup file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-906'
  tag rid: 'SV-37192r1_rule'
  tag stig_id: 'GEN001580'
  tag gtitle: 'GEN001580'
  tag fix_id: 'F-32777r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
