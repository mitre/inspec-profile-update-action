control 'SRG-NET-000004-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must automatically disable user accounts after a 35-day period of account inactivity.'
  desc 'Attackers that are able to exploit an inactive account can potentially obtain and maintain undetected access to an application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. Unified Communications Session Managers must track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be misused, hijacked, or data compromised.

DOD has determined that 35 days is the appropriate time period of inactivity for Inactive accounts. Therefore, systems with a per user paradigm of management would apply.'
  desc 'check', 'Verify the Unified Communications Session Manager automatically disables Voice Video Endpoint user access after a 35-day period of account inactivity. This requirement refers to users rather than endpoints.

If the Unified Communications Session Manager does not automatically disable Voice Video Endpoint user access after a 35-day period of account inactivity, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to automatically disable Voice Video Endpoint user access after a 35-day period of account inactivity.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000004-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000004-VVSM-00101'
  tag rid: 'SRG-NET-000004-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000004-VVSM-00101'
  tag gtitle: 'SRG-NET-000004-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000004-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
