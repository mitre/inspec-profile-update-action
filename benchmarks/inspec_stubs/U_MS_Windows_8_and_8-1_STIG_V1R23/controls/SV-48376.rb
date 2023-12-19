control 'SV-48376' do
  title 'Hyper-V must not be installed on a workstation.'
  desc 'Allowing other operating systems to run on a secure system may allow users to circumvent security.'
  desc 'check', %q(Verify the Hyper-V platform has not been installed on the system.

Open Control Panel.
Select "Programs and Features".
Select "Turn Windows features on or off".
If "Hyper-V Platform" is selected, this is a finding.  (Hyper-V Platform is a subcategory under Hyper-V)

If Hyper-V is installed on a workstation, the organization must have an approved use case for it.  Any virtual OS's must be secured.  This would not be a finding.)
  desc 'fix', 'Uninstall the Hyper-V platform through "Turn Windows Features on or off".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45874r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36727'
  tag rid: 'SV-48376r3_rule'
  tag stig_id: 'WN08-GE-000021'
  tag gtitle: 'WN08-GE-000021'
  tag fix_id: 'F-43265r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
