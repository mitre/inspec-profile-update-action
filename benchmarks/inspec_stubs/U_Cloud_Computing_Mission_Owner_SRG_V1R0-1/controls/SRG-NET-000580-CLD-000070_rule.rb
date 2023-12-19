control 'SRG-NET-000580-CLD-000070_rule' do
  title 'The Mission Owner of the IaaS/PaaS must implement an encrypted, FIPS 140-2/3 compliant path between the implemented systems/applications and the DOD OCSP responders.'
  desc 'The Mission Owner must use identity services, to include an Online Certificate Status Protocol (OCSP) responder, for remote system DOD Common Access Card (CAC) two-factor authentication of DOD privileged (all Impact levels) and/or nonprivileged users (Impact levels 4–6) to systems instantiated within the cloud service environment.'
  desc 'check', 'Applies to all impact levels.

Verify that a FIPS 140-2/3 compliant communication protocol is configured for communication between the implemented systems/applications and the DOD OCSP responders.

If the cloud IaaS/PaaS does not implement a secure (encrypted) connection or path between the implemented systems/applications and the DOD OCSP responders, this is a finding.'
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP Moderate, High.

Configure the IaaS/PaaS to implement an encrypted path that is FIPS 140-3 compliant between the implemented systems/applications and the DOD OCSP responders.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000580-CLD-000070_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000580-CLD-000070'
  tag rid: 'SRG-NET-000580-CLD-000070_rule'
  tag stig_id: 'SRG-NET-000580-CLD-000070'
  tag gtitle: 'SRG-NET-000580-CLD-000070'
  tag fix_id: 'F-SRG-NET-000580-CLD-000070_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
