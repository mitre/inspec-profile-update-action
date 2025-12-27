control 'SV-233316' do
  title 'Forescout must send an alert to the Information System Security Manager (ISSM) and System Administrator (SA), at a minimum, when critical security issues are found that put the network at risk. This is required for compliance with C2C Step 2.'
  desc "Requiring authentication and authorization of both the user's identity and the identity of the computing device is essential to ensuring a non-authorized person or device has entered the network."
  desc 'check', 'If DoD is not at C2C Step 2 or higher, this is not a finding.

Verify Forescout performs device authentication before policy assessment is performed.

If device authentication is not completed prior to the NAC check, this is a finding.'
  desc 'fix', 'Log on to the Forescout UI. 

1. Locate the Authentication & Authorization policy.
2. Ensure the Authentication & Authorization policy happens prior to any NAC check.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36511r811380_chk'
  tag severity: 'medium'
  tag gid: 'V-233316'
  tag rid: 'SV-233316r811381_rule'
  tag stig_id: 'FORE-NC-000080'
  tag gtitle: 'SRG-NET-000015-NAC-000100'
  tag fix_id: 'F-36476r605652_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
