control 'SRG-NET-000205-CLD-000060_rule' do
  title 'The Mission Owner of the PaaS/IaaS must configure scanning using an Assured Compliance Assessment Solution (ACAS) server or solution that meets DOD scanning and reporting requirements.'
  desc 'Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws.

Implement scanning using an ACAS server IAW USCYBERCOM TASKORD 13-670.
   - Use an ACAS Security Center server within NIPRNet or within an associated common virtual services environment in the same CSO.
   - Implement a secure (encrypted) connection or path between the ACAS server and its assigned ACAS Security Center.

Impact Level 2: Applies to IaaS/PaaS CSOs where the Mission Owner has control over the environment. In this case, Mission Owners must provide their own enclave boundary protections or leverage an enterprise level application protection service (i.e., the Virtual Datacenter Security Stack [VDSS]/Virtual Datacenter Management Suite [VDMS] portion of the SCCA) instantiated within the same CSO.'
  desc 'check', 'If this is a SaaS, this is not applicable.

This applies to all Impact Levels.

Review the configuration of the IaaS/PaaS. Verify that the IP address of an ACAS server is configured. Verify the flaw remediation data is also being communicated to the Cybersecurity Service Provider (CSSP).

If the PaaS/IaaS does not implement scanning using an ACAS server or CSP provided solution that meets DOD scanning and reporting requirements, this is a finding.'
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP Moderate, High.

Configure the IP address of an ACAS server or another solution that meets DOD scanning and reporting requirements.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000205-CLD-000060_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000205-CLD-000060'
  tag rid: 'SRG-NET-000205-CLD-000060_rule'
  tag stig_id: 'SRG-NET-000205-CLD-000060'
  tag gtitle: 'SRG-NET-000205-CLD-000060'
  tag fix_id: 'F-SRG-NET-000205-CLD-000060_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
