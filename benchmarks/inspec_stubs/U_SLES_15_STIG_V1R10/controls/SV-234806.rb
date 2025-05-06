control 'SV-234806' do
  title 'The SUSE operating system must display the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access to the local graphical user interface (GUI).'
  desc 'The SUSE operating system must display the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access to the local graphical user interface (GUI).

'
  desc 'check', 'Verify the SUSE operating system displays the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on via the local GUI. 

Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Check the configuration by running the following command:

> more /etc/gdm/Xsession

The beginning of the file must contain the following text immediately after (#!/bin/sh):

if ! zenity --text-info \\
--title "Consent" \\
--filename=/etc/gdm/banner \\
--no-markup \\
--checkbox="Accept." 10 10; then
sleep 1;
exit 1;
fi

If the beginning of the file does not contain the above text immediately after the line (#!/bin/sh), this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to display the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access.

Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Edit the file "/etc/gdm/Xsession".

Add the following content to the file "/etc/gdm/Xsession" below the line #!/bin/sh:

if ! zenity --text-info \\
--title "Consent" \\
--filename=/etc/gdm/banner \\
--no-markup \\
--checkbox="Accept." 10 10; then
sleep 1;
exit 1;
fi

Save the file "/etc/gdm/Xsession".'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-37994r618687_chk'
  tag severity: 'medium'
  tag gid: 'V-234806'
  tag rid: 'SV-234806r622137_rule'
  tag stig_id: 'SLES-15-010050'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-37957r618688_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end
