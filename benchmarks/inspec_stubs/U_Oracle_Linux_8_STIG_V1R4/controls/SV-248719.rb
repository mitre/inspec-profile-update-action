control 'SV-248719' do
  title 'OL 8 default permissions must be defined in such a way that all authenticated users can read and modify only their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.'
  desc 'check', 'Verify OL 8 defines default permissions for all authenticated users in such a way that the user can read and modify only their own files with the following command: 
 
$ sudo grep -i "umask" /etc/login.defs 
 
UMASK 077 
 
If the "UMASK" variable is set to "000", this is a finding with the severity raised to a CAT I. 
 
If the value of "UMASK" is not set to "077", "UMASK" is commented out, or "UMASK" is missing completely, this is a finding.'
  desc 'fix', 'Configure OL 8 to define the default permissions for all authenticated users in such a way that the user can read and modify only their own files. 
 
Edit the "UMASK" parameter in the "/etc/login.defs" file to match the example below: 
 
UMASK 077'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52153r779721_chk'
  tag severity: 'medium'
  tag gid: 'V-248719'
  tag rid: 'SV-248719r779723_rule'
  tag stig_id: 'OL08-00-020351'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-52107r779722_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
