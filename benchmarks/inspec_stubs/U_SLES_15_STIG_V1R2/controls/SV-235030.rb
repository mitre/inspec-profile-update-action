control 'SV-235030' do
  title 'The SUSE operating system default permissions must be defined in such a way that all authenticated users can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.'
  desc 'check', 'Verify the SUSE operating system defines default permissions for all authenticated users in such a way that the users can only read and modify their own files. 

Check the system default permissions with the following command:

> grep -i "^umask" /etc/login.defs

UMASK 077

If the "UMASK" variable is set to "000", the severity is raised to a CAT I, and this is a finding.

If the value of "UMASK" is not set to "077", or "UMASK" is missing, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to define the default permissions for all authenticated users in such a way that the users can only read and modify their own files.

Add or edit the "UMASK" parameter in the "/etc/login.defs" file to match the example below:

UMASK 077'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38218r619359_chk'
  tag severity: 'medium'
  tag gid: 'V-235030'
  tag rid: 'SV-235030r622137_rule'
  tag stig_id: 'SLES-15-040420'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-38181r619360_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
