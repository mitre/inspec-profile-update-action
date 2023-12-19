control 'SV-254246' do
  title 'Windows Server 2022 domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.'
  desc 'Credential Guard uses virtualization-based security to protect data that could be used in credential theft attacks if compromised. A number of system requirements must be met in order for Credential Guard to be configured and enabled properly. Without a TPM enabled and ready for use, Credential Guard keys are stored in a less secure method using software.'
  desc 'check', 'For standalone or nondomain-joined systems, this is NA.

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
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57731r848552_chk'
  tag severity: 'medium'
  tag gid: 'V-254246'
  tag rid: 'SV-254246r848554_rule'
  tag stig_id: 'WN22-00-000090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57682r848553_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
