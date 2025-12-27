control 'SV-252945' do
  title 'TOSS must not allow an unattended or automatic logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify TOSS does not allow an unattended or automatic logon to the system via a graphical user interface.

Note: This requirement assumes the use of the TOSS default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Check for the value of the "AutomaticLoginEnable" in the "/etc/gdm/custom.conf" file with the following command:

$ sudo grep -i automaticloginenable /etc/gdm/custom.conf
AutomaticLoginEnable=false

If the value of "AutomaticLoginEnable" is missing or is not set to "false", this is a finding. If it does, this is a finding. Automatic logon as an authorized user allows access to any user with physical access to the operating system.'
  desc 'fix', 'Configure TOSS to not allow an unattended or automatic logon to the system via a graphical user interface.

Add or edit the line for the "AutomaticLoginEnable" parameter in the [daemon] section of the "/etc/gdm/custom.conf" file to "false":

[daemon]
AutomaticLoginEnable=false'
  impact 0.7
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56398r824157_chk'
  tag severity: 'high'
  tag gid: 'V-252945'
  tag rid: 'SV-252945r824159_rule'
  tag stig_id: 'TOSS-04-010430'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-56348r824158_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
