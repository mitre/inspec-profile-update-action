control 'SV-253255' do
  title 'Windows 11 domain-joined systems must have a Trusted Platform Module (TPM) enabled.'
  desc 'Credential Guard uses virtualization-based security to protect information that could be used in credential theft attacks if compromised. There are a number of system requirements that must be met in order for Credential Guard to be configured and enabled properly. Without a TPM enabled and ready for use, Credential Guard keys are stored in a less secure method using software.'
  desc 'check', 'Verify domain-joined systems have a TPM enabled and ready for use.

For standalone systems, this is NA.

Virtualization-based security, including Credential Guard, currently cannot be implemented in virtual desktop implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Verify the system has a TPM and is ready for use.
Run "tpm.msc".
Review the sections in the center pane.
"Status" must indicate it has been configured with a message such as "The TPM is ready for use" or "The TPM is on and ownership has been taken".
TPM Manufacturer Information - Specific Version = 2.0

If a TPM is not found or is not ready for use, this is a finding.'
  desc 'fix', 'For standalone systems, this is NA.

Virtualization-based security, including Credential Guard, currently cannot be implemented in virtual desktop implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Ensure domain-joined systems must have a TPM that is configured for use. (Versions 2.0 support Credential Guard.)

The TPM must be enabled in the firmware.
Run "tpm.msc" for configuration options in Windows.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56708r828847_chk'
  tag severity: 'medium'
  tag gid: 'V-253255'
  tag rid: 'SV-253255r828849_rule'
  tag stig_id: 'WN11-00-000010'
  tag gtitle: 'SRG-OS-000424-GPOS-00188'
  tag fix_id: 'F-56658r828848_fix'
  tag 'documentable'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
