control 'SV-234210' do
  title 'The FortiGate device must use FIPS 140-2 approved algorithms for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not validated and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Network devices utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. However, authentication algorithms must configure security processes to use only FIPS-approved and NIST-recommended authentication algorithms.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # get system status | grep -i fips
The output should be:         
             FIPS-CC mode: enable

If FIPS-CC mode parameter is not set to enable, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system fips-cc
          # set status enable
     # end'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37395r611817_chk'
  tag severity: 'high'
  tag gid: 'V-234210'
  tag rid: 'SV-234210r879616_rule'
  tag stig_id: 'FGFW-ND-000255'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-37360r611818_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
