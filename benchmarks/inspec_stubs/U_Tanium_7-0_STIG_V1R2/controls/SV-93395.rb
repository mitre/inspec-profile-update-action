control 'SV-93395' do
  title 'The Tanium Server certificate and private/public keys directory must be protected with appropriate permissions.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

Navigate to Program Files >> Tanium >> Tanium Server.

Right-click on the "Certs" folder.
Choose "Properties".
Select the "Security" tab.
Click on the "Advanced" button.

Validate the owner of the directory is the [Tanium service account].

Validate System has Read Only permissions.

Validate the [Tanium service account] has Read Only permissions.

Validate [Tanium Admins group] has Full permissions.

If the owner of the directory is not the [Tanium service account] and/or System and the [Tanium service account] has more privileges than Read Only and/or the [Tanium Admins group] has less than Full permissions, this is a finding.

Navigate to Program Files >> Tanium >> Tanium Server >> Certs.

Right-click on each of the following files:
Select "Properties".
Select the "Security" tab.
Click on the "Advanced" button.
Installedcacert.crt
Installed-server.crt
Installed-server.key
SOAPServer.crt
SOAPServer.key

Validate System and the [Tanium service account] have Read-Only permissions to each of the individual files, and the [Tanium Admin group] has Full permissions to each of the individual files.

If System and the [Tanium service account] have more than Read-Only permissions to any of the individual files and/or the [Tanium Admin group] has less than Full permissions to any of the individual files, this is a finding.

Navigate to Program Files >> Tanium >> Tanium Server >> content_public_keys.

Right-click on each of the following files:
Select "Properties".
Select the "Security" tab.
Click on the "Advanced" button.

Validate System has Read-Only permissions and is applied to child objects.

Validate [Tanium service account] has Read-Only permissions and is applied to child objects.

Validate [Tanium Admin Group] has Full permissions and is applied to child objects.

If the [Tanium service account] and system permissions to the \\content_public_keys folder is greater than Read-Only and/or the Read-Only permissions have not been applied to child objects and/or the [Tanium Admin Group] has less than Full permissions, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

Navigate to Program Files >> Tanium >> Tanium Server.

Right-click on "Certs" folder.
Choose "Properties".
Select the "Security" tab.
Click on the "Advanced" button.

Change the owner of the directory to the [Tanium service account].

Reduce System and the [Tanium service account] to Read-Only permissions.

Provide the [Tanium Admin group] with Full permissions.

Navigate to >> Program Files >> Tanium >> Tanium Server >> Certs.

Right-click on each of the following files:
Select "Properties".
Select the "Security" tab.
Click on the "Advanced" button.

For the following files, reduce System and the [Tanium service account] to Read-Only:
Installedcacert.crt
Installed-server.crt
Installed-server.key
SOAPServer.crt
SOAPServer.key

Ensure the [Tanium Admin group] has Full permissions for those same files.

Navigate to >> Program Files >> Tanium >> Tanium Server >> content_public_keys.

Select "Properties".

Select the "Security" tab.

Click on the "Advanced" button.

Reduce System to Read-Only permissions. - apply to child objects.

Reduce [Tanium service account] to Read-Only permissions. - apply to child objects.

Provide [Tanium Admin group] with Full permissions - apply to child objects.'
  impact 0.7
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78259r1_chk'
  tag severity: 'high'
  tag gid: 'V-78689'
  tag rid: 'SV-93395r1_rule'
  tag stig_id: 'TANS-SV-000021'
  tag gtitle: 'SRG-APP-000176'
  tag fix_id: 'F-85425r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
