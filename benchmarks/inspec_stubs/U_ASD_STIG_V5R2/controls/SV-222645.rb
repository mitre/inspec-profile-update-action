control 'SV-222645' do
  title 'Application files must be cryptographically hashed prior to deploying to DoD operational networks.'
  desc 'When application code and binaries are transferred from one environment to another, there is the potential for malware to be introduced into either the application code or even the application binaries themselves. Care must be taken to ensure that application code and binaries are validated for integrity prior to deployment into a production environment.

To ensure file integrity, application files and/or application packages are cryptographically hashed using a strong hashing algorithm. Comparing hashes after transferring the files makes it possible to detect changes in files that could indicate potential integrity issues with the application.

Currently, SHA256 is the DoD approved standard for cryptographic hash functions. DoD application developers must use SHA256 when creating cryptographic hashes; however, some non-DoD vendors might still use MD5 or SHA1 when generating a checksum hash for their application packages. It is important to use the same algorithms when validating the hash. If a non DoD vendor uses SHA1 when hashing their files, you must use SHA1 to validate the hash. Otherwise, the hashes will not match and a false positive indication of tampering will result.

Prior to release of the application receiving an ATO/IATO for deployment into a DoD operational network, the application must be validated for integrity to ensure no tampering of source code or binaries has occurred. Failure to validate the integrity of application code and/or application binaries prior to deploying an application into a production environment may compromise the operational network.'
  desc 'check', %q(Ask the application representative to demonstrate their cryptographic hash validation process or provide process documentation. The validation process will vary based upon the operating system used as there are numerous clients available that will display a file's cryptographic hash for validation purposes.

Linux operating systems include the "sha256sum" utility. For Linux systems using sha256sum command syntax is: sha256sum [OPTION]... [FILE]...

Recent Windows PowerShell versions include the "get-filehash" PowerShell cmdlet. The default algorithm value used is SHA256.

Syntax is: 
Get-FileHash
[-Path] <String[]>
[-Algorithm <String>]
[<CommonParameters>] 

A validation process involves obtaining the application files’ cryptographic hash value from the programs author or other authoritative source such as the application's website. A utility like the "sha256sum" utility is then run using the downloaded application file name as the argument. The output is the files' hash value. The two hash values are compared and if they match, then file integrity is ensured.

If the application being reviewed is a COTS product and the vendor used a SHA1 or MD5 algorithm to generate a hash value, this is not a finding.

If the application being reviewed is a COTS product and the vendor did not provide a hash value for validating the package, this is not a finding.

If the integrity of the application files/code is not validated prior to deployment to DoD operational networks, this is a finding.)
  desc 'fix', 'Developers/release managers create cryptographic hash values of application files and/or application packages prior to transitioning the application from test to a production environment. They protect cryptographic hash information so it cannot be altered and make a read copy of the hash information available to application Admins so they can validate application packages and files after they download the files.

Application Admins validate cryptographic hashes prior to deploying the application to production.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36256r602331_chk'
  tag severity: 'medium'
  tag gid: 'V-222645'
  tag rid: 'SV-222645r864427_rule'
  tag stig_id: 'APSC-DV-003140'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-36220r602332_fix'
  tag 'documentable'
  tag legacy: ['SV-84991', 'V-70369']
  tag cci: ['CCI-000698']
  tag nist: ['SA-10 (1)']
end
