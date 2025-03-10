control 'SV-255251' do
  title 'The SSMC web server must use cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised due to weak algorithms. 

FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules. 

The web server must provide FIPS-compliant encryption modules when authenticating users and processes.

'
  desc 'check', 'Verify that SSMC utilizes FIPS 140-2 approved mode of encryption for authenticating users by doing the following:

1. Log on to SSMC Administrator Console on web GUI as ssmcadmin. 

2. Click the information icon on top right corner and verify "FIPS mode enabled" displays "true".

3. Log on to SSMC appliance as ssmcadmin via SSH, press "X" to escape to general bash shell from the TUI menu, and issue the following command:

$ sudo /ssmc/bin/config_security.sh -o fips_mode -a status
The output of the command must read "FIPS mode is enabled".

If the observations do not indicate FIPS mode as enabled in both steps 1 and 2, this is a finding.'
  desc 'fix', 'Configure SSMC to utilize FIPS 140-2 approved mode of encryption for authenticating users by doing the following:

1. Log on to the SSMC administrator console as "ssmcadmin" and enable FIPS 140-2 mode.

a. Navigate to Actions >> Preferences >> FIPS 140-2 Enabled setting and toggle the switch to "yes". Select "OK". 

2. Log on as "ssmcadmin" on the appliance and enable FIPS 140-2 approved mode by doing the following: 

a. Press "X" to escape to general bash shell.

b. Execute the following command:

$ sudo /ssmc/bin/config_security.sh -o fips_mode -a enable

c. Reboot the appliance when prompted.'
  impact 0.7
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58864r869920_chk'
  tag severity: 'high'
  tag gid: 'V-255251'
  tag rid: 'SV-255251r869922_rule'
  tag stig_id: 'SSMC-WS-010010'
  tag gtitle: 'SRG-APP-000179-WSR-000111'
  tag fix_id: 'F-58808r869921_fix'
  tag satisfies: ['SRG-APP-000179-WSR-000111', 'SRG-APP-000014-WSR-000006', 'SRG-APP-000015-WSR-000014', 'SRG-APP-000179-WSR-000110', 'SRG-APP-000224-WSR-000135', 'SRG-APP-000224-WSR-000136', 'SRG-APP-000224-WSR-000139', 'SRG-APP-000416-WSR-000118', 'SRG-APP-000439-WSR-000156', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-001188', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002422', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'IA-7', 'SC-23 (3)', 'AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (2)', 'SC-13 b']
end
