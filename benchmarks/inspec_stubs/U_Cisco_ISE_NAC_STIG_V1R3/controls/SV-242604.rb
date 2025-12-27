control 'SV-242604' do
  title 'Before establishing a local, remote, and/or network connection with any endpoint device, the Cisco ISE must use a bidirectional authentication mechanism configured with a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to authenticate with the endpoint device. This is required for compliance with C2C Step 1.'
  desc 'Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk. Currently, DoD requires the use of AES for bidirectional authentication since it is the only FIPS-validated AES cipher block algorithm.

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to apply the requirement only to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.

From the Web Admin portal:
1. Navigate to Administration >> System >> Settings >> Security Settings.
2. Ensure "Allow TLS1.0", "Allow TLS1.1", and "Allow legacy unsafe TLS renegotiation for ISE as a client" are unchecked. 

If TLS 1.0 or 1.1 is enabled, this is a finding.'
  desc 'fix', 'From the Web Admin portal:
1. Navigate to Administration >> System >> Settings >> Security Settings.
2. Ensure "Allow TLS1.0", "Allow TLS1.1", and "Allow legacy unsafe TLS renegotiation for ISE as a client" are unchecked.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45879r812789_chk'
  tag severity: 'medium'
  tag gid: 'V-242604'
  tag rid: 'SV-242604r812790_rule'
  tag stig_id: 'CSCO-NC-000300'
  tag gtitle: 'SRG-NET-000151-NAC-000630'
  tag fix_id: 'F-45836r714121_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
