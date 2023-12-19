control 'SV-252968' do
  title 'TOSS must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.'
  desc 'check', 'Verify TOSS defines default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Check for the value of the "UMASK" parameter in "/etc/login.defs" file with the following command:

Note: If the value of the "UMASK" parameter is set to "000" in "/etc/login.defs" file, the Severity is raised to a CAT I.

$ grep -i umask /etc/login.defs
UMASK 077

If the value for the "UMASK" parameter is not "077", or the "UMASK" parameter is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Add or edit the line for the "UMASK" parameter in "/etc/login.defs" file to "077":

UMASK 077'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56421r824226_chk'
  tag severity: 'medium'
  tag gid: 'V-252968'
  tag rid: 'SV-252968r824228_rule'
  tag stig_id: 'TOSS-04-020290'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-56371r824227_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
