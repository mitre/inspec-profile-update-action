control 'SV-222555' do
  title 'The application must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'A cryptographic module is a hardware or software device or component that performs cryptographic operations securely within a physical or logical boundary, using a hardware, software or hybrid cryptographic engine contained within the boundary, and cryptographic keys that do not leave the boundary.
Based on the criticality of the application, system designers might choose to utilize a hardware based cryptographic module due to the protections and security benefits a hardware based solution provides over a software based solution. Due to various factors, including expense, hardware based encryption modules are usually relegated to only those applications where the system requirements specify it as a required protection. Examples include applications that handle extremely sensitive data or those used in life and death situations, e.g., weapons systems. 

General purpose applications such as a web site will often opt to leverage an underlying software based encryption capability that is offered by the OS, database or application development framework.  Operating systems or database products often provide their own cryptographic modules that are FIPS 140-2 compliant and can meet the authentication to the crypto module requirement via their Role Based Access Controls (users and groups) built into the product.  
In all cases, user’s accessing the cryptographic module must be authenticated and granted the appropriate rights in order to access the encryption module.  Any encryption utilized by the access control mechanisms must be FIPS 140-2 compliant.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify if the application provides access to cryptographic modules and if access is required in order to manage cryptographic modules contained within the application.

If the application does not provide authenticated access to a cryptographic module, the requirement is not applicable.

Review and identify the cryptographic module. Refer to the NIST website listing all FIPS-approved cryptographic modules.

http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm

If the cryptographic module that requires authentication is not on the FIPS-approved module list, this is a finding.'
  desc 'fix', 'Use FIPS-approved cryptographic modules.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24225r493573_chk'
  tag severity: 'high'
  tag gid: 'V-222555'
  tag rid: 'SV-222555r865215_rule'
  tag stig_id: 'APSC-DV-001860'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-24214r493574_fix'
  tag 'documentable'
  tag legacy: ['V-70159', 'SV-84781']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
