control 'SV-51291' do
  title 'Network infrastructure and systems supporting the test and development environment must be registered in a DoD asset management system.'
  desc "An asset management system is used to send out notifications on vulnerabilities in commercial and military information infrastructures as they are discovered.  If the organization's assets are not registered with an asset management system, administrators will not be notified of important vulnerabilities such as viruses, denial of service attacks, system weaknesses, back doors, and other potentially harmful situations.  Additionally, there will be no way to enter, track, or resolve findings during a review."
  desc 'check', 'Determine whether all systems and network infrastructure devices supporting the test and development environment are registered in an asset management system.  If any systems and network infrastructure devices supporting the test and development environment are not registered in an asset management system, this is a finding.'
  desc 'fix', 'Register the network infrastructure and systems supporting the test and development environment in a DoD asset management program.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46812r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39433'
  tag rid: 'SV-51291r1_rule'
  tag stig_id: 'ENTD0030'
  tag gtitle: 'ENTD0030 - The test and development infrastructure registered in DoD asset management program.'
  tag fix_id: 'F-44446r2_fix'
  tag 'documentable'
  tag ia_controls: 'VIVM-1'
end
