control 'SV-18043' do
  title 'Virtual machines are not configured with the correct posture in VMS.'
  desc 'Correctly configuring virtual machine assets in VMS will ensure that the appropriate vulnerabilities are assigned to the asset. If the asset is not configured with the correct posture, vulnerabilities may be open on the asset.  These open vulnerabilities may allow an attacker access to the system.'
  desc 'check', 'Verify the correct postures are configured for virtual machine assets.  If there are many assets, check a sampling of the total virtual machines registered. 

    UNIX (Linux or Unix) or Windows (Windows OS Version)
    VMware Virtual Machine

If the virtual machine is not registered or is not registered properly, this is a finding.'
  desc 'fix', 'Configure the virtual machine with the proper posture in VMS.'
  impact 0.5
  ref 'DPMS Target VMware Virtual Machine 3.x/4.x'
  tag check_id: 'C-17721r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17043'
  tag rid: 'SV-18043r1_rule'
  tag stig_id: 'ESX1220'
  tag gtitle: 'Virtual Machines with incorrect posture in VMS'
  tag fix_id: 'F-16847r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Guest Administrator]']
end
