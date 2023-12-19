control 'SV-255953' do
  title 'The Arista network device must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Step 1: Verify on the Arista network device that an account of last resort is configured using the following command:

switch#sh running-config | section username
username Emergency-Admin privilege 15 role network-admin secret sha512 $6$ObuWg.Eu7DwGD8k/$EgT0uI.hLrStrmxUvJijecxDXr.Zy.imi1UrDzDP38q8Erqgkfe0IhHzIhYmR3ekW74XdAFf7I6SgzAoUFd0

Step 2: Verify the Arista network device default account has been overwritten with the local account of last resort.

switch#sh running-config | section username
username Emergency-Admin privilege 15 role network-admin secret sha512 $6$ObuWg.Eu7DwGD8k/$EgT0uI.hLrStrmxUvJijecxDXr.Zy.imi1UrDzDP38q8Erqgkfe0IhHzIhYmR3ekW74XdAFf7I6SgzAoUFd0

If one local account on the Arista network device does not exist for use as the account of last resort in the event the authentication server is unavailable, this is a finding.

If the default admin account exists on the device, this is a finding.'
  desc 'fix', 'Step 1: Configure the Arista network device for a username "Emergency-Admin" account of last resort using the following command:

switch#configure
switch(config)#username Emergency-Admin privilege 15 role network-admin secret 0  <plain-text password> 

Step 2: Ensure the Arista network device default account has been overwritten with the local account of last resort.

switch#sh running-config | section username
username Emergency-Admin privilege 15 role network-admin secret sha512 $6$ObuWg.Eu7DwGD8k/$EgT0uI.hLrStrmxUvJijecxDXr.Zy.imi1UrDzDP38q8Erqgkfe0IhHzIhYmR3ekW74XdAFf7I6SgzAoUFd0
!

Use the following command to remove the default admin account if necessary:

switch(config)#no username admin

Step 3: As a final step in the case all administrative accounts are locked out of the device, ensure the username and password created for the account of last resort is contained within a sealed envelope and kept in a safe or secure network location.'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59629r882199_chk'
  tag severity: 'medium'
  tag gid: 'V-255953'
  tag rid: 'SV-255953r882201_rule'
  tag stig_id: 'ARST-ND-000350'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-59572r882200_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002041', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'IA-5 (1) (f)', 'AC-2 a']
end
