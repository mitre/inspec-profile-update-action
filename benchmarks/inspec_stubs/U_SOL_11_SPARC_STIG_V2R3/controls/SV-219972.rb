control 'SV-219972' do
  title 'The operating system must disable information system functionality that provides the capability for automatic execution of code on mobile devices without user direction.'
  desc 'Mobile devices include portable storage media (e.g., USB memory sticks, external hard disk drives) and portable computing and communications devices with information storage capability (e.g., notebook/laptop computers, personal digital assistants, cellular telephones, digital cameras, audio recording devices). 

Auto execution vulnerabilities can result in malicious programs being automatically executed. Examples of information system functionality providing the capability for automatic execution of code are Auto Run and Auto Play. Auto Run and Auto Play are components of the Microsoft Windows operating system that dictate what actions the system takes when a drive is mounted. This requirement is designed to address vulnerabilities that arise when mobile devices such as USB memory sticks or other mobile storage devices are automatically mounted and applications are automatically invoked without user knowledge or acceptance.'
  desc 'check', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine if the removable media volume manager is running.

# svcs -Ho state svc:/system/filesystem/rmvolmgr:default

If the output reports that the service is "online", this is a finding.'
  desc 'fix', 'The Service Management profile is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Disable the rmvolmgr service.

# pfexec svcadm disable svc:/system/filesystem/rmvolmgr:default'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-21682r371048_chk'
  tag severity: 'medium'
  tag gid: 'V-219972'
  tag rid: 'SV-219972r603267_rule'
  tag stig_id: 'SOL-11.1-030060'
  tag gtitle: 'SRG-OS-000183'
  tag fix_id: 'F-21681r371049_fix'
  tag 'documentable'
  tag legacy: ['V-47939', 'SV-60811']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
