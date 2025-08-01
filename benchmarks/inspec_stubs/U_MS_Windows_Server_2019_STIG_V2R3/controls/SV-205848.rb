control 'SV-205848' do
  title 'Windows Server 2019 domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.'
  desc 'Credential Guard uses virtualization-based security to protect data that could be used in credential theft attacks if compromised. A number of system requirements must be met in order for Credential Guard to be configured and enabled properly. Without a TPM enabled and ready for use, Credential Guard keys are stored in a less secure method using software.'
  desc 'check', 'For standalone systems, this is NA.

Current hardware and virtual environments may not support virtualization-based security features, including Credential Guard, due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within a virtual machine.

Verify the system has a TPM and it is ready for use.

Run "tpm.msc".

Review the sections in the center pane.

"Status" must indicate it has been configured with a message such as "The TPM is ready for use" or "The TPM is on and ownership has been taken".

TPM Manufacturer Information - Specific Version = 2.0 or 1.2

If a TPM is not found or is not ready for use, this is a finding.'
  desc 'fix', 'Ensure domain-joined systems have a TPM that is configured for use. (Versions 2.0 or 1.2 support Credential Guard.)

The TPM must be enabled in the firmware.

Run "tpm.msc" for configuration options in Windows.'
  impact 0.5
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-6113r355906_chk'
  tag severity: 'medium'
  tag gid: 'V-205848'
  tag rid: 'SV-205848r569188_rule'
  tag stig_id: 'WN19-00-000090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-6113r355907_fix'
  tag 'documentable'
  tag legacy: ['V-93213', 'SV-103301']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
