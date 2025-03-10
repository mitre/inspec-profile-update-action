control 'SV-216082' do
  title 'Systems services that are not required must be disabled.'
  desc 'Services that are enabled but not required by the mission may provide excessive access or additional attack vectors to penetrate the system.'
  desc 'check', 'Determine all of the systems services that are enabled on the system.

# svcs -a | grep online

Document all enabled services and disable any that are not required.'
  desc 'fix', 'The Service Management profile is required:

Disable any other service not required. 

# pfexec svcadm disable [service name]'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17320r372628_chk'
  tag severity: 'low'
  tag gid: 'V-216082'
  tag rid: 'SV-216082r603268_rule'
  tag stig_id: 'SOL-11.1-030040'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17318r372629_fix'
  tag 'documentable'
  tag legacy: ['V-47933', 'SV-60805']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
