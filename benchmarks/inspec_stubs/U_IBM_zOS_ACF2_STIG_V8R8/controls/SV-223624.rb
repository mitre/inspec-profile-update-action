control 'SV-223624' do
  title 'IBM z/OS UNIX MVS data sets or HFS objects must be properly protected.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

'
  desc 'check', 'Refer to the proper BPXPRMxx member in SYS1.PARMLIB 

If the ESM data set rules for the data sets referenced in the ROOT and the MOUNT statements in BPXPRMxx restrict update access to the z/OS UNIX kernel (i.e., OMVS or OMVSKERN), this is not a finding.

If the ESM data set rules for the data sets referenced in the ROOT and the MOUNT statements in BPXPRMxx restrict update and/or allocate access to systems programming personnel, this is not a finding.'
  desc 'fix', 'Review the access authorizations defined in the ACP for the MVS data sets that contain operating system components and for the MVS data sets that contain HFS file systems and ensure that they conform to the specifications below Review the UNIX permission bits on the HFS directories and files and ensure that they conform to the specifications below:

Define ESM data set rules for the data sets referenced in the ROOT and the MOUNT statements in BPXPRMxx to restrict update access to the z/OS UNIX kernel (i.e., OMVS or OMVSKERN).

Define ESM data set rules for the data sets referenced in the ROOT and the MOUNT statements in BPXPRMxx to restrict update and/or allocate access to systems programming personnel.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25297r504830_chk'
  tag severity: 'medium'
  tag gid: 'V-223624'
  tag rid: 'SV-223624r533198_rule'
  tag stig_id: 'ACF2-US-000090'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25285r504831_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['V-97953', 'SV-107057']
  tag cci: ['CCI-000213', 'CCI-001499']
  tag nist: ['AC-3', 'CM-5 (6)']
end
