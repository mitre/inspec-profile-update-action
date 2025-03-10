control 'SRG-NET-000205-CLD-000040_rule' do
  title "The Mission Owner's internet-facing applications must be configured to traverse the CAP and VDSS prior to communicate with the internet."
  desc 'The Cloud Access Point (CAP) and Virtual Datacenter Security Stack (VDSS) architectures mitigate potential damages to the DISN and provide the ability to detect and prevent an attack before reaching the DISN. 

All traffic bound for the internet will traverse the BCAP/ICAP and IAP. Mission applications may be internet-facing; internet-facing applications can be non-restricted or restricted (requiring CAC authentication). DOD users on the internet may first connect into their assigned DISN Virtual Private Network (VPN) network before accessing Mission Owner enclave or private applications.'
  desc 'check', 'If this is a SaaS, this is not a finding.
If Impact Level 2, but CSP has control over the environment, this is not a finding.

Verify that virtual internet-facing applications are configured to traverse the CAP and VDSS prior to communicating with the internet.

If virtual internet-facing applications permit direct access to the CSP or the internet, this is a finding.'
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP Moderate, High.

Configure virtual internet-facing applications to traverse the CAP and VDSS prior to communicating with the internet.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000205-CLD-000040_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000205-CLD-000040'
  tag rid: 'SRG-NET-000205-CLD-000040_rule'
  tag stig_id: 'SRG-NET-000205-CLD-000040'
  tag gtitle: 'SRG-NET-000205-CLD-000040'
  tag fix_id: 'F-SRG-NET-000205-CLD-000040_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
