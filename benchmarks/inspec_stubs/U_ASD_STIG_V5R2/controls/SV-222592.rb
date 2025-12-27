control 'SV-222592' do
  title 'Applications must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files on storage) that may be assessed on specific information system components.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify if the application shares information resources via file sharing protocol or if the application includes configuration settings that provide access to data files on the hard drive.

Also determine if the application transfers data via shared system resources.

If the application shares system resources with other applications, verify that a security boundary exists which controls and prevents other applications, processes, or users from accessing application data. The control mechanism will vary based upon the resource that is being shared. Hard disk sharing could possibly utilize file permissions restrictions, whereas shared overall system resources could implement virtualization or containers that restrict access.

If the application does not prevent unauthorized and unintended information transfer via shared system resources, this is a finding.'
  desc 'fix', 'Configure or design the application to utilize a security control that will implement a boundary that will prevent unauthorized and unintended information transfer via shared system resources.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24262r493684_chk'
  tag severity: 'medium'
  tag gid: 'V-222592'
  tag rid: 'SV-222592r508029_rule'
  tag stig_id: 'APSC-DV-002380'
  tag gtitle: 'SRG-APP-000243'
  tag fix_id: 'F-24251r493685_fix'
  tag 'documentable'
  tag legacy: ['SV-84857', 'V-70235']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
