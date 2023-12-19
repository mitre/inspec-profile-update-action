control 'SV-68733' do
  title 'The ALG that is part of a CDS must enforce dynamic traffic flow control based on organization-defined policies.'
  desc 'Information flow policies regarding dynamic information flow control include allowing or disallowing information flows based on changing conditions or mission/operational considerations. Changing conditions include changes in organizational risk tolerance due to changes in the immediacy of mission/business needs, changes in the threat environment, and detection of potentially harmful or adverse events.

Organization-defined policies for CDS systems depend on the environment, data, and security boundaries. Organizations implementing CDS must follow the DoD-required process of testing, baselining, and risk assessment to ensure the rigor and accuracy necessary to rely upon a CDS for cross domain security.

Enforcement occurs in boundary protection devices that employ rule sets or establish configuration settings that restrict information system services, provide a packet filtering capability based on header information, or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

This requirement is primarily used by organizations with cross domain solution needs. These solutions require advanced filtering techniques and flow enforcement mechanisms, such as high-assurance guards. Dynamic traffic flow control mechanisms are generally not available in commercial off-the-shelf information technology products.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify changes made to the policy filters (e.g., rules sets or content filters) take effect immediately. The change in the filter must be applied to active sessions as well as new sessions without the need for restart of recompiling.

If the ALG does not enforce dynamic traffic flow control based on organization-defined policies, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to enforce dynamic flow control based on organization-defined policies.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55103r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54487'
  tag rid: 'SV-68733r1_rule'
  tag stig_id: 'SRG-NET-000029-ALG-000079'
  tag gtitle: 'SRG-NET-000029-ALG-000079'
  tag fix_id: 'F-59341r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000027', 'CCI-000366']
  tag nist: ['AC-4 (3)', 'CM-6 b']
end
