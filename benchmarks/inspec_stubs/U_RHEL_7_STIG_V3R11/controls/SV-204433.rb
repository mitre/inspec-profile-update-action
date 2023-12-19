control 'SV-204433' do
  title 'The Red Hat Enterprise Linux operating system must not allow an unrestricted logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify the operating system does not allow an unrestricted logon to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Check for the value of the "TimedLoginEnable" parameter in "/etc/gdm/custom.conf" file with the following command:

# grep -i timedloginenable /etc/gdm/custom.conf
TimedLoginEnable=false

If the value of "TimedLoginEnable" is not set to "false", this is a finding.'
  desc 'fix', 'Configure the operating system to not allow an unrestricted account to log on to the system via a graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Add or edit the line for the "TimedLoginEnable" parameter in the [daemon] section of the "/etc/gdm/custom.conf" file to "false":

[daemon]
TimedLoginEnable=false'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4557r88491_chk'
  tag severity: 'high'
  tag gid: 'V-204433'
  tag rid: 'SV-204433r877377_rule'
  tag stig_id: 'RHEL-07-010450'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-4557r88492_fix'
  tag 'documentable'
  tag legacy: ['V-71955', 'SV-86579']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
