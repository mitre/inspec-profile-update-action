control 'SV-221718' do
  title 'The Oracle Linux operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.'
  desc 'check', 'Verify the operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Check for the value of the "UMASK" parameter in "/etc/login.defs" file with the following command:

Note: If the value of the "UMASK" parameter is set to "000" in "/etc/login.defs" file, the Severity is raised to a CAT I.

# grep -i umask /etc/login.defs
UMASK 077

If the value for the "UMASK" parameter is not "077", or the "UMASK" parameter is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Add or edit the line for the "UMASK" parameter in "/etc/login.defs" file to "077":

UMASK 077'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23433r419226_chk'
  tag severity: 'medium'
  tag gid: 'V-221718'
  tag rid: 'SV-221718r603260_rule'
  tag stig_id: 'OL07-00-020240'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-23422r419227_fix'
  tag 'documentable'
  tag legacy: ['V-99173', 'SV-108277']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
