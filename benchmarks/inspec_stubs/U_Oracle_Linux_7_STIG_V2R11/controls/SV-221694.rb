control 'SV-221694' do
  title 'The Oracle Linux operating system must not allow an unattended or automatic logon to the system via a graphical user interface.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify the operating system does not allow an unattended or automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check for the value of the "AutomaticLoginEnable" in the "/etc/gdm/custom.conf" file with the following command:

# grep -i automaticloginenable /etc/gdm/custom.conf
AutomaticLoginEnable=false

If the value of "AutomaticLoginEnable" is not set to "false", this is a finding.'
  desc 'fix', 'Configure the operating system not to allow an unattended or automatic logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Add or edit the line for the "AutomaticLoginEnable" parameter in the [daemon] section of the "/etc/gdm/custom.conf" file to "false":

[daemon]
AutomaticLoginEnable=false'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23409r419154_chk'
  tag severity: 'high'
  tag gid: 'V-221694'
  tag rid: 'SV-221694r877377_rule'
  tag stig_id: 'OL07-00-010440'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-23398r419155_fix'
  tag 'documentable'
  tag legacy: ['V-99127', 'SV-108231']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
