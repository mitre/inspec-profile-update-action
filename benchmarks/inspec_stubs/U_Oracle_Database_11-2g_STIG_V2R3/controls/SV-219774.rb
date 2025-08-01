control 'SV-219774' do
  title 'The DBMS must support organizational requirements to enforce password encryption for storage.'
  desc 'Applications must enforce password encryption when storing passwords. Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read and easily compromised.

Database passwords stored in clear text are vulnerable to unauthorized disclosure. Database passwords must always be encoded or encrypted when stored internally or externally to the DBMS.'
  desc 'check', '(Oracle stores and displays its passwords in encrypted form.  Nevertheless, this should be verified by reviewing the relevant system views, along with the other items to be checked here.)

Ask the DBA to review the list of DBMS database objects, database configuration files, associated scripts, and applications defined within and external to the DBMS that access the database. The list should also include files, tables or settings used to configure the operational environment for the DBMS and for interactive DBMS user accounts.

Ask the DBA and/or IAO to determine if any DBMS database objects, database configuration files, associated scripts, and applications defined within or external to the DBMS that access the database, and DBMS/user environment files/settings/tables, contain database passwords. If any do, confirm that DBMS passwords stored internally or externally to the DBMS are encoded or encrypted. If any passwords are stored in clear text, this is a finding.

Ask the DBA/SA/Application Support staff if they have created an external password store for applications, batch jobs, and scripts to use.  Verify that all passwords stored there are encrypted.  If a password store is used and any password is not encrypted, this is a finding.


The following are notes on implementing a Secure External Password Store using Oracle Wallet:

You can store password credentials for connecting to databases by using a client-side Oracle wallet. An Oracle wallet is a secure software container that stores authentication and signing credentials.

This wallet usage can simplify large-scale deployments that rely on password credentials for connecting to databases. When this feature is configured, application code, batch jobs, and scripts  no longer need embedded user names and passwords. This reduces risk because the passwords are no longer exposed, and password management policies are more easily enforced without changing application code whenever user names or passwords change.
  
The external password store of the wallet is separate from the area where public key infrastructure (PKI) credentials are stored. Consequently, you cannot use Oracle Wallet Manager to manage credentials in the external password store of the wallet. Instead, use the command-line utility mkstore to manage these credentials.
  
How Does the External Password Store Work?

Typically, users (and applications, batch jobs, and scripts) connect to databases by using a standard CONNECT statement that specifies a database connection string. This string can include a user name and password, and an Oracle Net service name identifying the database on an Oracle Database network. If the password is omitted, the connection prompts the user for the password.

For example, the service name could be the URL that identifies that database, or a TNS alias you entered in the tnsnames.ora file in the database. Another possibility is a host:port:sid string.
  
The following examples are standard CONNECT statements that could be used for a client that is not configured to use the external password store:

  CONNECT salesapp@sales_db.us.example.com
  Enter password: password

  CONNECT salesapp@orasales
  Enter password: password

  CONNECT salesapp@ourhost37:1527:DB17
  Enter password: password

In these examples, salesapp is the user name, with the unique connection string for the database shown as specified in three different ways. You could use its URL sales_db.us.example.com, or its TNS alias, orasales, from the tnsnames.ora file, or its host:port:sid string.

However, when clients are configured to use the secure external password store, applications can connect to a database with the following CONNECT statement syntax, without specifying database logon credentials:

  CONNECT /@db_connect_string

  CONNECT /@db_connect_string AS SYSDBA

  CONNECT /@db_connect_string AS SYSOPER
  
In this specification, db_connect_string is a valid connection string to access the intended database, such as the service name, URL, or alias as shown in the earlier examples. Each user account must have its own unique connection string; you cannot create one connection string for multiple users.

In this case, the database credentials, user name and password, are securely stored in an Oracle wallet created for this purpose. The autologin feature of this wallet is turned on, so the system does not need a password to open the wallet. From the wallet, it gets the credentials to access the database for the user they represent.'
  desc 'fix', 'Develop, document, and maintain a list of DBMS database objects, database configuration files, associated scripts, and applications defined within or external to the DBMS that access the database, and DBMS/user environment files/settings in the System Security Plan.

Record whether they do or do not contain DBMS passwords. If passwords are present, ensure they are encoded or encrypted and protected by host system security.


The following are notes on implementing a Secure External Password Store using Oracle Wallet:

Oracle provides the capability to provide for a secure external password facility.  Use the Oracle mkstore to create a secure storage area for passwords for applications, batch jobs, and scripts to use, or deploy a site-authorized facility to perform this function.

Check to see what has been stored in the Oracle External Password Store.

To view all contents of a client wallet external password store, check specific credentials by viewing them. Listing the external password store contents provides information you can use to decide whether to add or delete credentials from the store.  To list the contents of the external password store, enter the following command at the command line:

$ mkstore -wrl wallet_location -listCredential
For example:
$ mkstore -wrl c:\\oracle\\product\\11.2.0\\db_1\\wallets -listCredential

The wallet_location specifies the path to the directory where the wallet, whose external password store contents you want to view, is located. This command lists all of the credential database service names (aliases) and the corresponding user name (schema) for that database. Passwords are not listed.

Configuring Clients to use the External Password Store:

If your client is already configured to use external authentication, such as Windows native authentication or Transport Layer Security (TLS), then Oracle Database uses that authentication method. The same credentials used for this type of authentication are typically also used to log in to the database.

For clients not using such authentication methods or wanting to override them for database authentication, you can set the SQLNET.WALLET_OVERRIDE parameter in sqlnet.ora to TRUE. The default value for SQLNET.WALLET_OVERRIDE is FALSE, allowing standard use of authentication credentials as before.

If you want a client to use the secure external password store feature, then perform the following configuration task:

1. Create a wallet on the client by using the following syntax at the command line:

mkstore -wrl wallet_location -create

For example:

mkstore -wrl c:\\oracle\\product\\11.2.0\\db_1\\wallets -create

Enter password: password

The wallet_location is the path to the directory where you want to create and store the wallet. This command creates an Oracle wallet with the autologin feature enabled at the location you specify. The autologin feature enables the client to access the wallet contents without supplying a password. 
 
The mkstore utility -create option uses password complexity verification.
 
2. Create database connection credentials in the wallet by using the following syntax at the command line:

mkstore -wrl wallet_location -createCredential db_connect_string username

Enter password: password

For example:
mkstore -wrl c:\\oracle\\product\\11.2.0\\db_1\\wallets -createCredential oracle system

Enter password: password

In this specification the wallet_location is the path to the directory where you created the wallet.  The db_connect_string used in the CONNECT /@db_connect_string statement must be identical to the db_connect_string specified in the -createCredential command.  The db_connect_string is the TNS alias you use to specify the database in the tnsnames.ora file or any service name you use to identify the database on an Oracle network. By default, tnsnames.ora is located in the $ORACLE_HOME/network/admin directory on UNIX systems and in ORACLE_HOME\\network\\admin on Windows.  The username is the database logon credential. When prompted, enter the password for this user.
 
 3. In the client sqlnet.ora file, enter the WALLET_LOCATION parameter and set it to the directory location of the wallet you created in Step 1.  For example, if you created the wallet in $ORACLE_HOME/network/admin and your Oracle home is set to /private/ora11, then you need to enter the following into your client sqlnet.ora file:

    WALLET_LOCATION =
           (SOURCE =
             (METHOD = FILE)
             (METHOD_DATA =
           (DIRECTORY = /private/ora11/network/admin)
           )
          )
 
4. In the client sqlnet.ora file, enter the SQLNET.WALLET_OVERRIDE parameter and set it to TRUE as follows:

SQLNET.WALLET_OVERRIDE = TRUE

This setting causes all CONNECT /@db_connect_string statements to use the information in the wallet at the specified location to authenticate to databases.

When external authentication is in use, an authenticated user with such a wallet can use the CONNECT /@db_connect_string syntax to access the previously specified databases without providing a user name and password. However, if a user fails that external authentication, then these connect statements also fail.

Below is a sample sqlnet.ora file with the WALLET_LOCATION and the SQLNET.WALLET_OVERRIDE parameters set as described in Steps 3 and 4.

        WALLET_LOCATION =
            (SOURCE =
              (METHOD = FILE)
              (METHOD_DATA =
            (DIRECTORY = /private/ora11/network/admin)
              )
             )
        SQLNET.WALLET_OVERRIDE = TRUE
        SSL_CLIENT_AUTHENTICATION = FALSE
        SSL_VERSION = 1.2

(Note: This assumes that a single sqlnet.ora file, in the default location, is in use. Please see the supplemental file "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or differently located sqlnet.ora files.)'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21499r307171_chk'
  tag severity: 'medium'
  tag gid: 'V-219774'
  tag rid: 'SV-219774r397522_rule'
  tag stig_id: 'O112-C2-014600'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-21498r307172_fix'
  tag 'documentable'
  tag legacy: ['SV-66501', 'V-52285']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
