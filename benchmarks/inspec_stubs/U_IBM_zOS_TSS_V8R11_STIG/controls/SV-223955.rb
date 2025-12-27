control 'SV-223955' do
  title 'The CA-TSS AUTOERASE Control Option must be set to ALL for all systems.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the AUTOERASE Control Option value is set to (ALL), this is not a finding.'
  desc 'fix', 'Configure the AUTOERASE control option is set to (ALL) for all systems to erase all residual information on DASD. Evaluate the impact associated with implementation of the control option. Develop a plan of action to set the AUTOERASE control option to (ALL) for all systems and implement.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25628r516264_chk'
  tag severity: 'medium'
  tag gid: 'V-223955'
  tag rid: 'SV-223955r877796_rule'
  tag stig_id: 'TSS0-ES-000820'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-25616r516265_fix'
  tag 'documentable'
  tag legacy: ['SV-107721', 'V-98617']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
