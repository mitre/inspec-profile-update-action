control 'SRG-NET-000512-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to use the organization authoritative time source (NTP) to maintain system time.'
  desc 'Configuring the network element to implement organizationwide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DOD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network element. Security-related parameters are those parameters impacting the security state of the network element, including the parameters required to satisfy other security control requirements. For the network element, security-related parameters include settings for network traffic management configurations.'
  desc 'check', 'Verify the Unified Communications Session Manager is configured to use the organization authoritative time source (NTP).

If the Unified Communications Session Manager is not configured to use the organization authoritative time source, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to use the organization authoritative time source.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000512-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000512-VVSM-00101'
  tag rid: 'SRG-NET-000512-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000512-VVSM-00101'
  tag gtitle: 'SRG-NET-000512-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000512-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
