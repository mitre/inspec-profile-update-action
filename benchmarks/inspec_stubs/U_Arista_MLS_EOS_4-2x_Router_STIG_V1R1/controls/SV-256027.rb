control 'SV-256027' do
  title 'The Arista BGP router must be configured to use a unique key for each autonomous system (AS) that it peers with.'
  desc 'If the same keys are used between eBGP neighbors, the chance of a hacker compromising any of the BGP sessions increases. It is possible that a malicious user exists in one autonomous system who would know the key used for the eBGP session. This user would then be able to hijack BGP sessions with other trusted neighbors.'
  desc 'check', 'Interview the ISSM and router administrator to determine if unique keys are being used.

Verify the BGP router AS is configured for a unique key. Run the command "sh run | section router bgp".

router bgp [NN]
neighbor [ip address] password [type] [password-string]

If unique keys are not being used, this is a finding.'
  desc 'fix', 'Configure all eBGP Arista routers with unique keys for each eBGP neighbor that it peers with.

To configure BGP authentication, in the BGP configuration mode interface, when adding neighbors, include the following statement:

router bgp NN
neighbor 100.1.0.0  password 0 [password-string]'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59703r882421_chk'
  tag severity: 'medium'
  tag gid: 'V-256027'
  tag rid: 'SV-256027r882423_rule'
  tag stig_id: 'ARST-RT-000470'
  tag gtitle: 'SRG-NET-000230-RTR-000002'
  tag fix_id: 'F-59646r882422_fix'
  tag 'documentable'
  tag cci: ['CCI-002205']
  tag nist: ['AC-4 (17)']
end
