control 'SV-38493' do
  title 'All local initialization files must have mode 0740 or less permissive.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'fix', %q(Ensure user startup files have permissions of 0740 or more restrictive. Examine each user's home directory and verify all file names beginning with "." have access permissions of 0740 or more restrictive. If they do not, use the chmod command to correct the vulnerability. 

Procedure: 
# chmod 0740 .filename 

NOTE: The period is part of the file name and is required.)
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-905'
  tag rid: 'SV-38493r1_rule'
  tag stig_id: 'GEN001880'
  tag gtitle: 'GEN001880'
  tag fix_id: 'F-31704r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
