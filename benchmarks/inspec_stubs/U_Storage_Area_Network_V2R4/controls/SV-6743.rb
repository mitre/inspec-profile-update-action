control 'SV-6743' do
  title 'Vendor supported, DOD approved, anti-virus software is not installed and configured on all SAN servers in accordance with the applicable operating system STIG on SAN servers and management devices and kept up-to-date with the most recent virus definition tables.'
  desc 'The SAN servers and other hosts are subject to virus and worm attacks as are any systems running an OS.  If the anti-virus software is not installed or the virus definitions are not maintained on these systems, this could expose the entire enclave network to exploits of known vulnerabilities.
The IAO/NSO will ensure that vendor supported, DOD approved, anti-virus software is installed and configured on all SAN servers in accordance with the applicable operating system STIG on SAN servers and management devices and kept up-to-date with the most recent virus definition tables.'
  desc 'check', 'The reviewer will verify that vendor supported, DOD approved, anti-virus software is installed and configured on all SAN servers in accordance with the applicable operating system STIG on SAN servers and management devices and kept up-to-date with the most recent virus definition tables.  If an OS review has reciently been completed verify that the anti-virus check was not a finding.  Otherwise perform a manual check as described in the applicable OS checklist.'
  desc 'fix', 'Install and correctly configure a DOD approved anti-virus.'
  impact 0.7
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2472r1_chk'
  tag severity: 'high'
  tag gid: 'V-6623'
  tag rid: 'SV-6743r1_rule'
  tag stig_id: 'SAN04.006.00'
  tag gtitle: 'Anti-virus on servers and host.'
  tag fix_id: 'F-6212r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end
