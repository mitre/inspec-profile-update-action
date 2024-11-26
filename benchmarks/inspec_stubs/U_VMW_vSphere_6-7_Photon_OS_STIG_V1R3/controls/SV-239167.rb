control 'SV-239167' do
  title 'The Photon operating system must be configured so that the /etc/skel default scripts are protected from unauthorized modification.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'At the command line, execute the following command:

# stat -c "%n permissions are %a and owned by %U:%G" /etc/skel/.[^.]*

Expected result:

/etc/skel/.bash_logout permissions are 750 and owned by root:root
/etc/skel/.bash_profile permissions are 644 and owned by root:root
/etc/skel/.bashrc permissions are 750 and owned by root:root

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, execute the following commands:

# chmod 750 /etc/skel/.bash_logout
# chmod 644 /etc/skel/.bash_profile
# chmod 750 /etc/skel/.bashrc
# chown root:root /etc/skel/.bash_logout
# chown root:root /etc/skel/.bash_profile
# chown root:root /etc/skel/.bashrc'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42378r675307_chk'
  tag severity: 'medium'
  tag gid: 'V-239167'
  tag rid: 'SV-239167r675309_rule'
  tag stig_id: 'PHTN-67-000096'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42337r675308_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
