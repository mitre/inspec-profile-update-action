control 'SV-237734' do
  title 'DBMS passwords must not be stored in compiled, encoded, or encrypted batch jobs or compiled, encoded, or encrypted application source code.'
  desc "Password maximum lifetime is  the maximum period of time, (typically in days) a user's password may be in effect before the user is forced to change it.

Passwords need to be changed at specific policy-based intervals as per policy. Any password, no matter how complex, can eventually be cracked.

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.

The storage of passwords in application source or batch job code that is compiled, encoded, or encrypted prevents compliance with password expiration and other management requirements, as well as provides another means for potential discovery.

This requirement applies equally to those accounts managed by Oracle and those managed and authenticated by the OS or an enterprise-wide mechanism.  

This requirement should not be construed as prohibiting or discouraging the encryption of source code, which remains an advisable precaution.

Transport Layer Security (TLS) is the successor protocol to Secure Sockets Layer (SSL). Although the Oracle configuration parameters have names including 'SSL', such as SSL_VERSION and SSL_CIPHER_SUITES, they refer to TLS.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered."
  desc 'check', 'Review application source code required to be encoded or encrypted for database accounts used by applications or batch jobs to access the database.

Review source batch job code prior to compiling, encoding, or encrypting for database accounts used by applications or the batch jobs themselves to access the database.

Determine if the compiled, encoded, or encrypted application source code or batch jobs contain passwords used for authentication to the database.

If any of the identified compiled, encoded, or encrypted application source code or batch job code do contain passwords used for authentication to the database, this is a finding.

- - - - -
The check would depend on the information provided by the DBA.  In a default Oracle installation, all passwords are stored in an encrypted manner.  Ask the DBA if they have created an External Password Store for applications, batch jobs, and scripts to use.

Secure External Password Store

Can store password credentials for connecting to databases by using a client-side Oracle wallet. An Oracle wallet is a secure software container that stores authentication and signing credentials.

This wallet usage can simplify large-scale deployments that rely on password credentials for connecting to databases. When this feature is configured, application code, batch jobs, and scripts no longer need embedded user names and passwords. This reduces risk because the passwords are no longer exposed, and password management policies are more easily enforced without changing application code whenever user names or passwords change.

The external password store of the wallet is separate from the area where public key infrastructure (PKI) credentials are stored. Consequently, cannot use Oracle Wallet Manager to manage credentials in the external password store of the wallet. Instead, use the command-line utility mkstore to manage these credentials.

How Does the External Password Store Work?

Typically, users (and as applications, batch jobs, and scripts) connect to databases by using a standard CONNECT statement that specifies a database connection string. This string can include a user name and password, and an Oracle Net service name identifying the database on an Oracle Database network. If the password is omitted, the connection prompts the user for the password.

For example, the service name could be the URL that identifies that database, or a TNS alias entered in the tnsnames.ora file in the database. Another possibility is a host:port:sid string.

The following examples are standard CONNECT statements that could be used for a client that is not configured to use the external password store:

  CONNECT salesapp@sales_db.us.example.com
  Enter password: password

  CONNECT salesapp@orasales
  Enter password: password

  CONNECT salesapp@ourhost37:1527:DB17
  Enter password: password

In these examples, salesapp is the user name, with the unique connection string for the database shown as specified in three different ways. Could use its URL sales_db.us.example.com, or its TNS alias, orasales, from the tnsnames.ora file, or its host:port:sid string.

However, when clients are configured to use the secure external password store, applications can connect to a database with the following CONNECT statement syntax, without specifying database logon credentials:

  CONNECT /@db_connect_string

  CONNECT /@db_connect_string AS SYSDBA

  CONNECT /@db_connect_string AS SYSOPER
  
In this specification, db_connect_string is a valid connection string to access the intended database, such as the service name, URL, or alias as shown in the earlier examples. Each user account must have its own unique connection string; cannot create one connection string for multiple users.

In this case, the database credentials, user name and password, are securely stored in an Oracle wallet created for this purpose. The autologon feature of this wallet is turned on, so the system does not need a password to open the wallet. From the wallet, it gets the credentials to access the database for the user they represent.'
  desc 'fix', 'Design DBMS application code and batch job code that is compiled, encoded or encrypted, to NOT contain passwords.

- - - - -
Oracle provides the capability to provide for a secure external password facility.  Use the Oracle mkstore to create a secure storage area for passwords for applications, batch jobs, and scripts to use or deploy a site-authorized facility to perform this function.

Check to see what has been stored in the Oracle External Password Store

To view all contents of a client wallet external password store, check specific credentials by viewing them. Listing the external password store contents provides information can use to decide whether to add or delete credentials from the store.  To list the contents of the external password store, enter the following command at the command line:

  $ mkstore -wrl wallet_location -listCredential

  For example:

  $ mkstore -wrl c:\\oracle\\product\\12.1.0\\db_1\\wallets -listCredential

The wallet_location specifies the path to the directory where the wallet, whose external password store contents is to be viewed, is located. This command lists all of the credential database service names (aliases) and the corresponding user name (schema) for that database. Passwords are not listed.

Configuring Clients to Use the External Password Store

If the client is already configured to use external authentication, such as Windows native authentication or Transport Layer Security (TLS), then Oracle Database uses that authentication method. The same credentials used for this type of authentication are typically also used to log on to the database.

For clients not using such authentication methods or wanting to override them for database authentication, can set the SQLNET.WALLET_OVERRIDE parameter in sqlnet.ora to TRUE. The default value for SQLNET.WALLET_OVERRIDE is FALSE, allowing standard use of authentication credentials as before.

If wanting a client to use the secure external password store feature, then perform the following configuration task:

 1. Create a wallet on the client by using the following syntax at the command line:

 mkstore -wrl wallet_location -create

    For example:

    mkstore -wrl c:\\oracle\\product\\12.1.0\\db_1\\wallets -create
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

 3. In the client sqlnet.ora file, enter the WALLET_LOCATION parameter and set it to the directory location of the wallet created in Step 1.  For example, if the wallet was created in
       $ORACLE_HOME/network/admin and Oracle home is set to /private/ora12, then need to enter the following into your client sqlnet.ora file:

    WALLET_LOCATION =
           (SOURCE =
             (METHOD = FILE)
             (METHOD_DATA =
           (DIRECTORY = /private/ora12/network/admin)
           )
          )

 4. In the client sqlnet.ora file, enter the SQLNET.WALLET_OVERRIDE parameter and set it to TRUE as follows:

       SQLNET.WALLET_OVERRIDE = TRUE

setting causes all CONNECT /@db_connect_string statements to use the information in the wallet at the specified location to authenticate to databases.

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
        SSL_VERSION = 1.2

(Note:  this assumes that a single sqlnet.ora file, in the default location, is in use.  Please see the supplemental file, "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or differently-located sqlnet.ora files.)'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40953r667232_chk'
  tag severity: 'medium'
  tag gid: 'V-237734'
  tag rid: 'SV-237734r667234_rule'
  tag stig_id: 'O121-C2-015100'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-40916r667233_fix'
  tag 'documentable'
  tag legacy: ['V-61737', 'SV-76227']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
