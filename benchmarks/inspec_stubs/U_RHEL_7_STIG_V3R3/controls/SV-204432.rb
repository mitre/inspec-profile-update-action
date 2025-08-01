control 'SV-204432' do
  title 'The Red Hat Enterprise Linux operating system must not allow an unattended or automatic logon to the system via a graphical user interface.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify the operating system does not allow an unattended or automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check for the value of the "AutomaticLoginEnable" in the "/etc/gdm/custom.conf" file with the following command:

# grep -i automaticloginenable /etc/gdm/custom.conf
AutomaticLoginEnable=false

If the value of "AutomaticLoginEnable" is not set to "false", this is a finding.'
  desc 'fix', 'Configure the operating system to not allow an unattended or automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Add or edit the line for the "AutomaticLoginEnable" parameter in the [daemon] section of the "/etc/gdm/custom.conf" file to "false":

[daemon]
AutomaticLoginEnable=false'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4556r88488_chk'
  tag severity: 'high'
  tag gid: 'V-204432'
  tag rid: 'SV-204432r603261_rule'
  tag stig_id: 'RHEL-07-010440'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-4556r88489_fix'
  tag 'documentable'
  tag legacy: ['V-71953', 'SV-86577']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
