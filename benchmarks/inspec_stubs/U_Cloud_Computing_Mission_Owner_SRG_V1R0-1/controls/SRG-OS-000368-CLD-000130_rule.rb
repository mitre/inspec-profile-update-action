control 'SRG-OS-000368-CLD-000130_rule' do
  title 'For IaaS and PaaS, the Mission Owner must register with SNAP.'
  desc "SNAP registration documentation should include designating a certified Cybersecurity Service Provider (CSSP) as the Tier 2 CND.

If applicable, the IP address of the cloud service must be configured IAW the Mission Owner's IP registration in SNAP so they do not repurpose an already registered IP for new services without updating the SNAP registration."
  desc 'check', 'Verify the CSP’s cloud service offering is registered in SNAP for the connection approval and it is the one being used in the cloud management portal.

If the IP address that is registered in SNAP is not configured for use with the approved cloud environment, this is a finding.'
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP Moderate, High.

Register the IaaS/PaaS CSP’s cloud service offering in SNAP for the connection approval. 

Also register the IP address that for use by the cloud service offering using the cloud management portal.'
  impact 0.5
  tag check_id: 'C-SRG-OS-000368-CLD-000130_chk'
  tag severity: 'medium'
  tag gid: 'SRG-OS-000368-CLD-000130'
  tag rid: 'SRG-OS-000368-CLD-000130_rule'
  tag stig_id: 'SRG-OS-000368-CLD-000130'
  tag gtitle: 'SRG-OS-000368-CLD-000130'
  tag fix_id: 'F-SRG-OS-000368-CLD-000130_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
