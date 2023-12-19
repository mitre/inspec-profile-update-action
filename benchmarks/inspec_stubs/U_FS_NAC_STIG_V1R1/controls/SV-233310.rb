control 'SV-233310' do
  title 'Endpoint policy assessment must proceed after the endpoint attempting access has been identified using an approved identification method such as IP address.'
  desc "Automated policy assessments must reflect the organization's current security policy so entry control decisions will happen only where remote endpoints meet the organization's security requirements. If the remote endpoints are allowed to connect to the organization's network without passing minimum-security controls, they become a threat to the entire network.

Organizational policy must be established for what Forescout will check on the host for the agent and agentless. The Forescout system security plan (SSP) will be used to assess compliance with the requirement since each SSP item must be configured.

Examples include, but are not limited to:
- Verification that anti-virus software is authorized, running, and virus signatures are up to date.
- Host-based firewall installed and configured according to the organization's security policy.
- Host IDS/IPS is installed, operational, and up to date.
- Uses the result of malware, anti-virus, and IDS scans and status as part of the assessment decision process.
- Required BIOS, operating system, browser, and office application patch levels.
- Performs an assessment of the list of running services.
- Test for the presence of DoD-required software.
- Test for presence of peer-to-peer software (not allowed)."
  desc 'check', %q(Determine if Forescout is configured to confirm endpoint policy assessment after the endpoint attempting access has been identified using an approved identification method.

1. Log on to the Forescout Administrator UI.
2. From the Home screen select the "Policy" tab.
3. Verify that policies exist that assess compliance in accordance with the SSP. 
4. Examples include, but are not limited to:
- Verification that anti-virus software is authorized, running, and virus signatures are up to date.
- Host-based firewall installed and configured according to the organization's security policy.
- Host IDS/IPS is installed, operational, and up to date.
- Uses the result of malware, anti-virus, and IDS scans and status as part of the assessment decision process.
- Required BIOS, operating system, browser, and office application patch levels.
- Performs an assessment of the list of running services.
- Test for the presence of DoD-required software.
- Test for presence of peer-to-peer software (not allowed).

If Forescout does not have existing compliance assessment policies, this is a finding.)
  desc 'fix', 'Configure Forescout to identify the endpoint. 

1. From the console on the Enterprise Manager console, select the Policy tab.
2. In accordance with the SSP, ensure that the endpoint compliance assessment policies have been configured and are functioning properly.'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36505r605633_chk'
  tag severity: 'high'
  tag gid: 'V-233310'
  tag rid: 'SV-233310r611394_rule'
  tag stig_id: 'FORE-NC-000020'
  tag gtitle: 'SRG-NET-000015-NAC-000030'
  tag fix_id: 'F-36470r605634_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
