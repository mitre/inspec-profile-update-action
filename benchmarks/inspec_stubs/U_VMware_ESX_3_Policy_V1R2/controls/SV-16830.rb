control 'SV-16830' do
  title 'The VMware-converter utility is not used for VMDK imports or exports.'
  desc 'There will be situations that require the import or export of VMDK files on the VMFS partition.  Importing and exporting disk files can also be done through the Virtual Infrastructure Client or service console by copying the files from VMFS mount and pasting them to a partition running ext3 file system. Utilizing the VMware-converter utility is required since the VMFS file system utilizes such large files. There are third-party converters available that may work with VMware virtual machines, however, none have been thoroughly tested or approved by VMware.'
  desc 'check', 'Ask the IAO/SA how they import and export VMDK files.  If they are using the VMware-converter utility, this is not a finding.  If they are using a third party converter, ensure that the converter is supported by the vendor.  This might require going to the vendor’s website and verifying the version used is supported.  If it is not, this is a finding.'
  desc 'fix', 'Use the VMware-converter for all import and export of VMDK files to VMFS partitions.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16248r1_chk'
  tag severity: 'low'
  tag gid: 'V-15889'
  tag rid: 'SV-16830r1_rule'
  tag stig_id: 'ESX0930'
  tag gtitle: 'VMware-converter utility not used for VMDK'
  tag fix_id: 'F-15849r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
