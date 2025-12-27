control 'SV-6768' do
  title 'The fabric switches must use DoD-approved PKI rather than proprietary or self-signed device certificates.'
  desc 'DOD PKI supplies better protection from malicious attacks than userid/password authentication and should be used anytime it is feasible.'
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify fabric switches are protected by DOD PKI. 

View the installed device certificates.

Verify a DoD -approved certificate is loaded. 

If any of the certificates have the name or identifier of a non-DoD- approved source in the Issuer field, this is a finding.'
  desc 'fix', 'Generate a new key-pair from a DoD-approved certificate issuer. Sites must consult the PKI/PKI pages on the http://iase.disa.mil/ website for procedures for NIPRNet and SIPRNet.'
  impact 0.3
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2526r2_chk'
  tag severity: 'low'
  tag gid: 'V-6634'
  tag rid: 'SV-6768r2_rule'
  tag stig_id: 'SAN04.011.00'
  tag gtitle: 'SAN Switch encryption and DOD PKI'
  tag fix_id: 'F-6229r2_fix'
  tag 'documentable'
  tag potential_impacts: 'Failure to develop a plan for the coordinated correction of these vulnerabilities across the SAN could lead to a denial of service caused by a disruption or failure of the SAN.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end
