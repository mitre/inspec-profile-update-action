control 'SV-242251' do
  title 'The TippingPoint TPS must have FIPS mode enforced.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

'
  desc 'check', 'In the SMS client:

1. Click Admin and Management.
2. Ensure the SMS is in FIPS Mode. 

If the SMS is not in FIPS mode, this is a finding.'
  desc 'fix', 'Enable the SMS FIPS Mode:

1. Click Admin and Management.
2. Click Enable FIPS Mode by selecting Edit. This must be done in an approved change window since the SMS will reboot.'
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45526r754433_chk'
  tag severity: 'high'
  tag gid: 'V-242251'
  tag rid: 'SV-242251r754441_rule'
  tag stig_id: 'TIPP-NM-000470'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-45484r754434_fix'
  tag satisfies: ['SRG-APP-000411-NDM-000330', 'SRG-APP-000412-NDM-000331']
  tag 'documentable'
  tag cci: ['CCI-002890', 'CCI-003123']
  tag nist: ['MA-4 (6)', 'MA-4 (6)']
end
