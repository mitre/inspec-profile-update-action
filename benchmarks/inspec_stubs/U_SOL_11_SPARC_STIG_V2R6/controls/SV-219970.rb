control 'SV-219970' do
  title 'The operating system must employ automated mechanisms, per organization-defined frequency, to detect the addition of unauthorized components/devices into the operating system.'
  desc 'Addition of unauthorized code or packages may result in data corruption or theft.'
  desc 'check', 'The Software Installation Profile is required.

Display the installation history of packages on the system to ensure that no undesirable packages have been installed:

# pkg history -o finish,user,operation,command |grep install

If the install command is listed as "/usr/bin/packagemanager", execute the command:

# pkg history -l 

to determine which packages were installed during package manager sessions.

If undocumented or unapproved packages have been installed, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

Review and report any unauthorized package installation operations.

If necessary, remove unauthorized packages.

# pfexec pkg uninstall [package name]'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-21680r370976_chk'
  tag severity: 'medium'
  tag gid: 'V-219970'
  tag rid: 'SV-219970r603267_rule'
  tag stig_id: 'SOL-11.1-020190'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-21679r370977_fix'
  tag 'documentable'
  tag legacy: ['V-47923', 'SV-60795']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
