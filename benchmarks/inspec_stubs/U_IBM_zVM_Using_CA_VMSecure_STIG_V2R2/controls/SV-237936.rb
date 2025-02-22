control 'SV-237936' do
  title 'CA VM:Secure AUTHORIZ CONFIG file must be properly configured.'
  desc 'Failure to provide logical access restrictions associated with changes to system configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the operating system can have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to operating system components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', %q(Examine "AUTHORIZ CONFIG" file.

If Authorizations are granted as follows, this is not a finding.

Grant the CA VM:Secure system administrator authorization to use all commands and menu selections.

Grant directory managers authorization to use a particular command, group of commands, or menu selection.

By carefully planning these authorizations, you can delegate many of the daily directory and disk space management tasks to the directory managers.

Plan these authorizations carefully to cover all aspects of your site's VM installation.

Grant general users authorization to use those commands and menu selections that enable them to manage their own virtual machine. Users can then perform tasks such as maintaining their own system password and controlling access to their minidisks by others.)
  desc 'fix', %q(Assure that the following authorizations are configured:

Grant the CA VM:Secure system administrator authorization to use all commands and menu selections.

Grant directory managers authorization to use a particular command, group of commands, or menu selection.

By carefully planning these authorizations, you can delegate many of the daily directory and disk space management tasks to the directory managers. Plan these authorizations carefully to cover all aspects of your site's VM installation.

Grant general users authorization to use those commands and menu selections that enable them to manage their own virtual machine. Users can then perform tasks such as maintaining their own system password and controlling access to their minidisks by others.

For example, for users in the Technical Support group, you may want to authorize them to use all selections on the "User Selection" menu.)
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41146r858998_chk'
  tag severity: 'medium'
  tag gid: 'V-237936'
  tag rid: 'SV-237936r859000_rule'
  tag stig_id: 'IBMZ-VM-000910'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-41105r858999_fix'
  tag 'documentable'
  tag legacy: ['SV-93625', 'V-78919']
  tag cci: ['CCI-001843']
  tag nist: ['AU-2 (3)']
end
