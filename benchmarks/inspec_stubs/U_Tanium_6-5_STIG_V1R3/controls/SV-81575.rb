control 'SV-81575' do
  title 'The Tanium Server certificate and private/public keys directory must be protected with appropriate permissions.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'Access the Tanium Server interactively. Log on with an account with administrative privileges to the server.

Open an Explorer window. 

Navigate to the \\Program Files\\Tanium\\Tanium Server folder.

Right-click on the \\Certs folder and choose “Properties”. 
Select the “Security” tab and click on the “Advanced” button.
Validate the owner of the directory is the [Tanium service account].
Validate System has Read Only permissions.

If the owner of the directory is not the [Tanium service account] and/or System has more privileges than Read Only, this is a finding.

Navigate to the \\Program Files\\Tanium\\Tanium Server\\Certs folder.

Right-click on each of the following files, select “Properties”.
Select the “Security” tab and click on the “Advanced” button.
Installedcacert.crt
Installed-server.crt
Installed-server.key
SOAPServer.crt
SOAPServer.key
Validate System and the [Tanium service account] have Read-Only permissions to each of the individual files.

If System and the [Tanium service account] have more than Read-Only permissions to any of the individual files, this is a finding.

Navigate to the \\Program Files\\Tanium\\Tanium Server\\content_public_keys folder.

Right-click on each of the following files, select “Properties”.
Select the “Security” tab and click on the “Advanced” button.
Validate the [Tanium service account] privileges to Read-Only.
Validate system privileges to Read-Only
Validate System has Read-Only permissions and is applied to child objects.
Validate [Tanium service account] has Read-Only permissions and is applied to child objects.

If the [Tanium service account] and system permissions to the \\content_public_keys folder is greater than Read-Only and/or the Read-Only permissions have not been applied to child objects, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively. Logon with an account with administrative privileges to the server.

Open an Explorer window.

Navigate to the \\Program Files\\Tanium\\Tanium Server folder.

Right-click on the \\Certs folder and choose “Properties”.

Select the “Security” tab and click on the “Advanced” button.

Change the owner of the directory to the [Tanium service account]. Reduce System to Read-Only permissions.

Navigate to the \\Program Files\\Tanium\\Tanium Server\\Certs folder.

Right-click on each of the following files, select “Properties”.

Select the “Security” tab and click on the “Advanced” button.

For the following files, reduce System and the [Tanium service account] to Read-Only:

Installedcacert.crt
Installed-server.crt
Installed-server.key
SOAPServer.crt
SOAPServer.key

Navigate to the \\Program Files\\Tanium\\Tanium Server folder.

Right-click on the \\content_public_keys folder, select “Properties”.

Select the “Security” tab and click on the “Advanced” button.

Reduce [Tanium service account] privileges to Read-Only.

Reduce system privileges to Read-Only.

Reduce System to Read-Only permissions. – apply to child objects.

Reduce [Tanium service account] to Read-Only permissions. – apply to child objects.'
  impact 0.7
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67721r1_chk'
  tag severity: 'high'
  tag gid: 'V-67085'
  tag rid: 'SV-81575r1_rule'
  tag stig_id: 'TANS-SV-000021'
  tag gtitle: 'SRG-APP-000176'
  tag fix_id: 'F-73185r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
