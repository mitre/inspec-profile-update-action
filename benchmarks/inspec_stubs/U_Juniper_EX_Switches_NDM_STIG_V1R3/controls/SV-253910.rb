control 'SV-253910' do
  title 'The Juniper EX switch must be configured to only store cryptographic representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Network devices must enforce cryptographic representations of passwords when storing passwords in databases, configuration files, and log files. Passwords must be protected at all times; using a strong one-way hashing encryption algorithm with a salt is the standard method for providing a means to validate a password without having to store the actual password.

Performance and time required to access are factors that must be considered, and the one-way hash is the most feasible means of securing the password and providing an acceptable measure of password security. If passwords are stored in clear text, they can be plainly read and easily compromised.

In many instances, verifying the user knows a password is performed using a password verifier. In its simplest form, a password verifier is a computational function that is capable of creating a hash of a password and determining if the value provided by the user matches the stored hash.'
  desc 'check', 'Review the network device’s files using a text editor or a database tool that allows viewing data stored in database tables. Determine if password strings are readable/discernable.
 
Determine if the network device, and any associated authentication servers, enforce only storing cryptographic representations of passwords. Verify that databases, configuration files, and log files have encrypted representations of all passwords, and that no password strings are readable/discernable. Potential locations include the local file system where configurations and events are stored, or in a network device related database table. Also identify if the network device uses the MD5 hashing algorithm to create password hashes.

By default, Junos uses SHA-512 as the password hashing algorithm to save only hashed representations of passwords. Verify the hashing algorithm at [edit system login password] format.

[edit system login password]
:
format sha512;

If the network device, or any associated authentication servers, stores unencrypted (clear text) representations of passwords, this is a finding.

If the network device uses MD5 hashing algorithm to create password hashes, this is a finding.'
  desc 'fix', 'Configure the network device, and any associated authentication servers, to store all passwords using cryptographic representations.

set system login password format <sha-256|sha-512>
Note: Although Junos supports the SHA-1 hashing algorithm, it is included only for backwards compatibility when restoring a previous configuration from an older version.

Configure all associated databases, configuration files, and log files to use only encrypted representations of passwords, and that no password strings are readable/discernable.

Potential locations include the local file system where configurations and events are stored, or in a network device-related database table.'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57362r843761_chk'
  tag severity: 'high'
  tag gid: 'V-253910'
  tag rid: 'SV-253910r879608_rule'
  tag stig_id: 'JUEX-NM-000330'
  tag gtitle: 'SRG-APP-000171-NDM-000258'
  tag fix_id: 'F-57313r843762_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
