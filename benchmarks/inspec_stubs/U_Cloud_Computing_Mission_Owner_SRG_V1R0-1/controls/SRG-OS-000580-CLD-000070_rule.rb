control 'SRG-OS-000580-CLD-000070_rule' do
  title 'The Mission Owner of the IaaS/PaaS must utilize valid DOD OCSP responders.'
  desc 'To provide assurances that certificates are validated by the correct responders. The Mission Owner must ensure they are using a valid DOD Online Certificate Status Protocol (OCSP) responder, for remote system DOD Common Access Card (CAC) two-factor authentication of DOD privileged users to systems instantiated within the cloud service environment.'
  desc 'check', 'Applies to all impact levels.

Verify that a valid DOD OCSP responder is configured for the implemented systems/applications

If the cloud IaaS/PaaS does not utilize an approved DOD OCSP responder, this is a finding.'
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP Moderate, High.

Configure the IaaS/PaaS to utilize an approved DOD OCSP responders.'
  impact 0.5
  tag check_id: 'C-SRG-OS-000580-CLD-000070_chk'
  tag severity: 'medium'
  tag gid: 'SRG-OS-000580-CLD-000070'
  tag rid: 'SRG-OS-000580-CLD-000070_rule'
  tag stig_id: 'SRG-OS-000580-CLD-000070'
  tag gtitle: 'SRG-OS-000580-CLD-000070'
  tag fix_id: 'F-SRG-OS-000580-CLD-000070_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
