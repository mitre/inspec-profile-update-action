control 'SV-223731' do
  title 'The IBM RACF ERASE ALL SETROPTS value must be set to ERASE(ALL) on all systems.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.'
  desc 'check', 'From the ISPF Command Shell enter:
SETRopts List

For all systems, if the ERASE values are set as follows, this is not a finding. 

ERASE-ON-SCRATCH IS ACTIVE, CURRENT OPTIONS: 
ERASE-ON-SCRATCH FOR ALL DATA SETS IS IN EFFECT'
  desc 'fix', 'Configure the ERASE SETROPTS value to ERASE(ALL) this allows DASD datasets to be erased when deleted.

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

-Issue the RACF Command SETR LIST to show the status of RACF Controls including the status of the ERASE options.

-Take the appropriate actions to ensure that the SETR ERASE(ALL) has been issued to enable Erase On Scratch for all datasets.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25404r514881_chk'
  tag severity: 'medium'
  tag gid: 'V-223731'
  tag rid: 'SV-223731r604139_rule'
  tag stig_id: 'RACF-ES-000840'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-25392r514882_fix'
  tag 'documentable'
  tag legacy: ['V-98169', 'SV-107273']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
