control 'SV-224010' do
  title 'IBM z/OS sensitive and critical system data sets must not exist on shared DASD.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.'
  desc 'check', 'Check HMC, VM, and z/OS on how to validate and determine a DASD volume(s) is shared.

Note: In VM issue the command "QUEUE DASD SYSTEM" this display will show shared volume(s) and indicates the number of systems sharing the volume.

Validate all machines that require access to these shared volume(s) have the volume(s) mounted.

Obtain a map or list VTOC of the shared volume(s).

Check if shared volume(s) contain any critical or sensitive data sets.

Identify shared and critical or sensitive data sets on the system being audited. These data sets can be APF, LINKLIST, LPA, Catalogs, etc, as well as product data sets.

If all of the critical or sensitive data sets identified on shared volume(s) are protected and justified to be on shared volume(s), this is not a finding.

List critical or sensitive data sets are possible security breaches, if not justified and not protected on systems having access to the data set(s) and on shared volume(s).'
  desc 'fix', 'Configure all identified volumes of shared DASD to be valid within the following.

HMC
VM
z/OS

If the shared volume(s) are valid and systems having access to these shared volume(s) are valid, map disk/VTOC list to obtain data sets on the shared volume(s). From this list obtain a list of sensitive and critical system data sets that are found on the shared volume(s). Ensure that the data sets are justified to be shared on the system and to reside on the shared volume(s).

The ISSO will review all access requirements to validate that sensitive and critical system data sets are protected from unauthorized access across all systems that have access to the shared volume(s). Protecting the data set(s) whether the data set(s) are used or not used on the systems that have the shared volume(s) available to them.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25683r516429_chk'
  tag severity: 'medium'
  tag gid: 'V-224010'
  tag rid: 'SV-224010r561402_rule'
  tag stig_id: 'TSS0-OS-000140'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-25671r516430_fix'
  tag 'documentable'
  tag legacy: ['SV-107833', 'V-98729']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
