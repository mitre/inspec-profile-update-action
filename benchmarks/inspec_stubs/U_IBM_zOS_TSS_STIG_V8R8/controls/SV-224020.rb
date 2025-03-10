control 'SV-224020' do
  title 'CA-TSS must be installed and properly configured.'
  desc 'Failure to provide logical access restrictions associated with changes to system configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the operating system can have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to operating system components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Refer to the active tasks on the system. Use IBM SDSF or the system Log.

If CA-TSS is active this is not a finding.'
  desc 'fix', 'Ensure that CA-TSS is active on the system.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25693r516459_chk'
  tag severity: 'high'
  tag gid: 'V-224020'
  tag rid: 'SV-224020r856119_rule'
  tag stig_id: 'TSS0-OS-000230'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-25681r516460_fix'
  tag 'documentable'
  tag legacy: ['SV-107851', 'V-98747']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
