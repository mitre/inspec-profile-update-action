control 'SV-217161' do
  title 'The SUSE operating system default permissions must be defined in such a way that all authenticated users can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.'
  desc 'check', 'Verify the SUSE operating system defines default permissions for all authenticated users in such a way that the users can only read and modify their own files. 

Check the system default permissions with the following command:

# grep -i "umask" /etc/login.defs

UMASK 077

If the "UMASK" variable is set to "000", the severity is raised to a CAT I, and this is a finding.

If the value of "UMASK" is not set to "077", "UMASK" is commented out, or "UMASK" is missing completely, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to define the default permissions for all authenticated users in such a way that the users can only read and modify their own files.

Add or edit the "UMASK" parameter in the "/etc/login.defs" file to match the example below:

UMASK 077'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18389r369639_chk'
  tag severity: 'medium'
  tag gid: 'V-217161'
  tag rid: 'SV-217161r603262_rule'
  tag stig_id: 'SLES-12-010620'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-18387r369640_fix'
  tag 'documentable'
  tag legacy: ['SV-91869', 'V-77173']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
