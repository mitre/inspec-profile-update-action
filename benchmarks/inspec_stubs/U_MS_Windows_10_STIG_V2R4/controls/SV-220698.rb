control 'SV-220698' do
  title 'Windows 10 domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.'
  desc 'Credential Guard uses virtualization based security to protect information that could be used in credential theft attacks if compromised. There are a number of system requirements that must be met in order for Credential Guard to be configured and enabled properly. Without a TPM enabled and ready for use, Credential Guard keys are stored in a less secure method using software.'
  desc 'check', 'Verify domain-joined systems have a TPM enabled and ready for use.

For standalone systems, this is NA.

Virtualization based security, including Credential Guard, currently cannot be implemented in virtual desktop implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Verify the system has a TPM and is ready for use.
Run "tpm.msc".
Review the sections in the center pane.
"Status" must indicate it has been configured with a message such as "The TPM is ready for use" or "The TPM is on and ownership has been taken".
TPM Manufacturer Information - Specific Version = 2.0 or 1.2

If a TPM is not found or is not ready for use, this is a finding.'
  desc 'fix', 'For standalone systems, this is NA.

Virtualization based security, including Credential Guard, currently cannot be implemented in virtual desktop implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Ensure domain-joined systems must have a Trusted Platform Module (TPM) that is configured for use. (Versions 2.0 or 1.2 support Credential Guard.)

The TPM must be enabled in the firmware.
Run "tpm.msc" for configuration options in Windows.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22413r554579_chk'
  tag severity: 'medium'
  tag gid: 'V-220698'
  tag rid: 'SV-220698r569187_rule'
  tag stig_id: 'WN10-00-000010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22402r554580_fix'
  tag 'documentable'
  tag legacy: ['V-63323', 'SV-77813']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
