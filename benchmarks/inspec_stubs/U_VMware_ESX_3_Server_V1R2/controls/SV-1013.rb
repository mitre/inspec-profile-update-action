control 'SV-1013' do
  title 'The system must be configured to only boot from the system boot device.'
  desc 'The ability to boot from removable media is the same as being able to boot into single user or maintenance mode without a password.  This ability could allow a malicious user to boot the system and perform changes possibly compromising or damaging the system.  It could also allow the system to be used for malicious purposes by a malicious anonymous user.'
  desc 'check', 'Determine if the system is configured to boot from devices other than the system startup media.  If so, this is a finding.

In most cases, this will require access to the BIOS or system controller.  The exact procedure will be hardware-dependent, and the SA should be consulted to identify the specific configuration.  In the event the BIOS or system controller is not accessible without adversely impacting (e.g., restarting) the system, the SA may be interviewed to determine compliance with the requirement.'
  desc 'fix', 'Configure the system to only boot from system startup media.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-1879r3_chk'
  tag severity: 'high'
  tag gid: 'V-1013'
  tag rid: 'SV-1013r2_rule'
  tag stig_id: 'GEN008600'
  tag gtitle: 'GEN008600'
  tag fix_id: 'F-1167r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
