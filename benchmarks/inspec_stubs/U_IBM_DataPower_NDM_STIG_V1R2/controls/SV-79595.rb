control 'SV-79595' do
  title 'The DataPower Gateway must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Network devices utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.'
  desc 'check', 'Default domain >> Status >> Cryptographic Mode Status: If Target=Permissive AND Current=Permissive AND Pending Target=Permissive, this is a finding.'
  desc 'fix', 'Administration >> Access >> RBM Settings >> Password Policy. Change Password hash algorithm to sha256crypt. 

Administration >> Miscellaneous >> Crypto Tools. Set Cryptographic Mode to FIPS 140-2 Level 1 and click Set Cryptographic Mode button. 

Control Panel >> System Control >> Shutdown. Set Mode to Reload Firmware >> Click "Shutdown" button.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65733r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65105'
  tag rid: 'SV-79595r1_rule'
  tag stig_id: 'WSDP-NM-000067'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-71045r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
