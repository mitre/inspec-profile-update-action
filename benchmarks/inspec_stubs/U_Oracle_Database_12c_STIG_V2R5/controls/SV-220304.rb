control 'SV-220304' do
  title 'When using command-line tools such as Oracle SQL*Plus, which can accept a plain-text password, users must use an alternative logon method that does not expose the password.'
  desc %q(The SRG states:  "To prevent the compromise of authentication information, such as passwords, during the authentication process, the feedback from the information system shall not provide any information that would allow an unauthorized user to compromise the authentication mechanism."

"Obfuscation of user-provided information when typed into the system is a method used in addressing this risk."

"For example, displaying asterisks when a user types in a password, is an example of obscuring feedback of authentication information."

"Database applications may allow for entry of the account name and password as a visible parameter of the application execution command. This practice should be prohibited and disabled to prevent shoulder surfing."

SQL*Plus is an essential part of any Oracle installation.  SQL*Plus cannot be configured not to accept a plain-text password.  Since the typical SQL*Plus user is a database administrator, the consequences of password compromise are particularly serious.  Therefore, the use of plain-text passwords must be prohibited, as a matter of practice and procedure.

Transport Layer Security (TLS) is the successor protocol to Secure Sockets Layer (SSL). Although the Oracle configuration parameters have names including 'SSL', such as SSL_VERSION and SSL_CIPHER_SUITES, they refer to TLS.)
  desc 'check', 'For Oracle SQL*Plus, which cannot be configured not to accept a plain-text password, and any other essential tool with the same limitation, verify that the system documentation explains the need for the tool, who uses it, and any relevant mitigations; and that AO approval has been obtained.  If not, this is a finding.

Request evidence that all users of the tool are trained in the importance of not using the plain-text password option and in how to keep the password hidden; and that they adhere to this practice.  If not, this is a finding.'
  desc 'fix', '"For Oracle SQL*Plus, which cannot be configured not to accept a plain-text password, and any other essential tool with the same limitation:

1) Document the need for it, who uses it, and any relevant mitigations, and obtain AO approval.
2) Train all users of the tool in the importance of not using the plain-text password option and in how to keep the password hidden.

- - - - -
Consider wrapping the startup command with a shell or wrapper and using an Oracle external password store.

Oracle provides the capability to provide for a secure external password facility.  Use the Oracle mkstore to create a secure storage area for passwords for applications, batch jobs, and scripts to use or deploy a site-authorized facility to perform this function.

Check to see what has been stored in the Oracle External Password Store.

To view all contents of a client wallet external password store, check specific credentials by viewing them. Listing the external password store contents provides information used to decide whether to add or delete credentials from the store.  To list the contents of the external password store, enter the following command at the command line:

  $ mkstore -wrl wallet_location -listCredential

  For example:

  $ mkstore -wrl c:\\oracle\\product\\12.1.0\\db_1\\wallets -listCredential

The wallet_location specifies the path to the directory where the wallet, whose external password store contents is to be viewed, is located. This command lists all of the credential database service names (aliases) and the corresponding user name (schema) for that database. Passwords are not listed.

Configuring Clients to Use the External Password Store

If the client is already configured to use external authentication, such as Windows native authentication or Transport Layer Security (TLS), then Oracle Database uses that authentication method. The same credentials used for this type of authentication are typically also used to log on to the database.

For clients not using such authentication methods or wanting to override them for database authentication, set the SQLNET.WALLET_OVERRIDE parameter in sqlnet.ora to TRUE. The default value for SQLNET.WALLET_OVERRIDE is FALSE, allowing standard use of authentication credentials as before.

If wanting a client to use the secure external password store feature, then perform the following configuration task:

1. Create a wallet on the client by using the following syntax at the command line:
orapki create -wallet wallet_location  -auto_login_local

For example:
orapki wallet create -wallet c:\\oracle\\product\\12.1.0\\db_1\\wallets -auto_login_local
Enter password: password

The wallet_location is the path to the directory where the wallet is to be created and stored. This command creates an Oracle wallet with the autologon feature enabled at the location specified. The autologon feature enables the client to access the wallet contents without supplying a password.

The mkstore utility -create option uses password complexity verification.

2. Create database connection credentials in the wallet by using the following syntax at the command line:
mkstore -wrl wallet_location -createCredential db_connect_string username
Enter password: password

For example:
mkstore -wrl c:\\oracle\\product\\12.1.0\\db_1\\wallets -createCredential oracle system
Enter password: password

In this specification:
The wallet_location is the path to the directory where the wallet was created.  The db_connect_string used in the CONNECT /@db_connect_string statement must be identical to the db_connect_string specified in the -createCredential command.

The db_connect_string is the TNS alias used to specify the database in the tnsnames.ora file or any service name used to identify the database on an Oracle network. By default, tnsnames.ora is located in the $ORACLE_HOME/network/admin directory on UNIX systems and in ORACLE_HOME\\network\\admin on Windows.

The username is the database logon credential. When prompted, enter the password for this user.

3. In the client sqlnet.ora file, enter the WALLET_LOCATION parameter and set it to the directory location of the wallet created in Step 1.  For example, if the wallet was created in $ORACLE_HOME/network/admin and the Oracle home is set to /private/ora12, then need to enter the following into the client sqlnet.ora file:

    WALLET_LOCATION =
           (SOURCE =
             (METHOD = FILE)
             (METHOD_DATA =
           (DIRECTORY = /private/ora12/network/admin)
           )
          )

4. In the client sqlnet.ora file, enter the SQLNET.WALLET_OVERRIDE parameter and set it to TRUE as follows:

       SQLNET.WALLET_OVERRIDE = TRUE

This setting causes all CONNECT /@db_connect_string statements to use the information in the wallet at the specified location to authenticate to databases.

When external authentication is in use, an authenticated user with such a wallet can use the CONNECT /@db_connect_string syntax to access the previously specified databases without providing a user name and password. However, if a user fails that external authentication, then these connect statements also fail.

Below is a sample sqlnet.ora file with the WALLET_LOCATION and the SQLNET.WALLET_OVERRIDE parameters set as described in Steps 3 and 4.

Below is a sample SQLNET.ORA File with Wallet Parameters Set

        WALLET_LOCATION =
            (SOURCE =
              (METHOD = FILE)
              (METHOD_DATA =
            (DIRECTORY = /private/ora12/network/admin)
              )
             )

        SQLNET.WALLET_OVERRIDE = TRUE
        SSL_CLIENT_AUTHENTICATION = FALSE
        SSL_VERSION =1.2

(Note: This assumes that a single sqlnet.ora file, in the default location, is in use. Please see the supplemental file "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or differently located sqlnet.ora files.)'
  impact 0.7
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22019r392043_chk'
  tag severity: 'high'
  tag gid: 'V-220304'
  tag rid: 'SV-220304r397603_rule'
  tag stig_id: 'O121-N1-015602'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-22011r392044_fix'
  tag 'documentable'
  tag legacy: ['SV-76335', 'V-61845']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
