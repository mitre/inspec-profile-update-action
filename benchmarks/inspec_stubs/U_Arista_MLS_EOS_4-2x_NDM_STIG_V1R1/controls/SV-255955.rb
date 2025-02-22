control 'SV-255955' do
  title 'The Arista network device must use FIPS 140-2 approved algorithms for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms used for authentication to the cryptographic module are not validated and therefore cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised.

Network devices utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DOD requirements. However, authentication algorithms must configure security processes to use only FIPS-approved and NIST-recommended authentication algorithms.'
  desc 'check', 'Determine if the Arista network device uses FIPS 140-2 approved algorithms for authentication to a cryptographic module.

Step 1: Review the Arista network device configuration to verify hardware or software entropy is enabled and FIPS restrictions are used in accordance with NIST-specified validated cryptographic requirements.

switch# show management security
CPU Model: AMD GX-424CC SOC with Radeon(TM) R5E Graphics
Security Chip: N313X
Crypto Module: Arista EOS Crypto Module v2.0
Forwarding ASIC: Jericho0 Model: Jericho
Blocked client protocols: None
Hardware entropy generation is enabled
Haveged entropy generation is disabled
Jitter entropy generation is disabled
!

If both hardware entropy and haveged entropy are disabled, this is a finding.

Step 2: Review the Arista network device configuration to verify that FIPS restrictions are enabled for management security to use EOS Crypto Module for the RSA key pair used for SSH and the device can only use FIPS-approved algorithms.

switch(config)show run | section management ssh
management ssh
   fips restrictions
!

If the FIPS restrictions line is not present, this is a finding.'
  desc 'fix', 'Configure the Arista network device to use FIPS 140-2 approved algorithms for authentication to a cryptographic module.

Step 1: Configure the Arista network device to ensure hardware or software entropy is enabled and FIPS restrictions are used in accordance with NIST-specified validated cryptographic requirements.

switch(config)#management security
   switch(config-mgmt-security)#entropy source hardware
OR (only set one or the other, not both)
   switch(config-mgmt-security)#entropy source haveged
!

Step 2: Configure the Arista network device to ensure the old RSA key pairs are zeroized and a new FIPS-approved hostkey is generated. It is extremely important to complete this step after hardware or software entropy is configured.

switch#reset ssh hostkey rsa
!
*IMPORTANT part of Step 2* Review the Arista network device configuration new key has been generated.

switch#show management ssh hostkey rsa public
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCz8vDiTWYcGuVrv04fwPj8YYBaHU+UFFl5zrFjeYiVl/dvswsiRSophF98aLjnRdJJ0NcjovjEEUnP0Q39UCoSYQRjrUzK2nzRMMD2IKxZyNhx9+/OT60lgh4M//kwxq0vMI1nk1pUO/wRaN1B4IzDizcyP9jY28bSdz8Y5TyLgrca6Ja4v99Io+lkHG0bj6X8s+VnBsFWMrlabw1s4bUPr9PzMfUHx9gLHCVR+DFZvPHMR4sSK14F949IJgOKsXj  chassisAddr=84:73:cf:6f:6c:55

Step 3: Enable FIPS restrictions for SSH and so the device can only use FIPS-approved algorithms.
 
switch(config)management ssh
switch(config-mgmt-ssh)#fips restrictions'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59631r882205_chk'
  tag severity: 'high'
  tag gid: 'V-255955'
  tag rid: 'SV-255955r882207_rule'
  tag stig_id: 'ARST-ND-000470'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-59574r882206_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
