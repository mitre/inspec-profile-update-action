control 'SV-221695' do
  title 'The Oracle Linux operating system must not allow an unrestricted logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify the operating system does not allow an unrestricted logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check for the value of the "TimedLoginEnable" parameter in "/etc/gdm/custom.conf" file with the following command:

# grep -i timedloginenable /etc/gdm/custom.conf
TimedLoginEnable=false

If the value of "TimedLoginEnable" is not set to "false", this is a finding.'
  desc 'fix', 'Configure the operating system not to allow an unrestricted account to log on to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Add or edit the line for the "TimedLoginEnable" parameter in the [daemon] section of the "/etc/gdm/custom.conf" file to "false":

[daemon]
TimedLoginEnable=false'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23410r419157_chk'
  tag severity: 'high'
  tag gid: 'V-221695'
  tag rid: 'SV-221695r877377_rule'
  tag stig_id: 'OL07-00-010450'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-23399r419158_fix'
  tag 'documentable'
  tag legacy: ['V-99129', 'SV-108233']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
