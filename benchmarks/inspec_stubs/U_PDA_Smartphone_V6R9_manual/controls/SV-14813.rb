control 'SV-14813' do
  title 'FIPS 140-2 validated encryption modules must be used to encrypt unclassified sensitive data at rest on the wireless device (e.g., laptop, PDA, smartphone).'
  desc 'If a wireless device is lost or stolen without DAR encryption, sensitive DoD data could be compromised.  Most known security breaches of cryptography result from improper implementation, not flaws in the cryptographic algorithms themselves.   FIPS 140-2 validation provides assurance that cryptography is implemented correctly, and is required for Federal Government uses of cryptography in non-classified applications.'
  desc 'check', 'Detailed Policy Requirements:

FIPS 140-2 validated encryption modules must be used to encrypt unclassified sensitive data at rest on the wireless device (e.g., laptop, PDA, smartphone).

This requirement applies to any wireless device or non-wireless PDA storing sensitive information, as defined by Assistant Secretary of Defense for Networks and Information Integration/DoD Chief Information Officer Memorandum, “Encryption of Sensitive Unclassified Data at Rest on Mobile Computing Devices and Removable Storage,” July 3, 2007.

This requirement also applies to removable memory cards (e.g., MicroSD) used in the PDA except when the PDA is connected to a Windows PC for the purpose of provisioning or transferring data. 

Check Procedures:

Interview IAO and review documentation.
1. Determine if the wireless device is used to store sensitive data.  Data approved for public release is not sensitive.  Other unclassified data may also qualify as sensitive.  Any device that stores any sensitive data must meet the requirements in this check. 
2. Check a sample of wireless laptops, PDAs, smartphones, and other wireless devices used at the site (2-3 of each type).
3. Obtain the product’s FIPS certificate to confirm FIPS 140-2 validation for each model examined.  The certificate may be obtained from the product documentation or the NIST web site.  
4. Work with the IAO to determine if encryption is enabled on the wireless client device uses AES or 3DES. 
5. Verify temp files with sensitive information are also protected with encryption.
6. Mark as a finding if encryption is not used or is not FIPS 140-2 validated.'
  desc 'fix', 'Employ FIPS 140-2 validated encryption modules for sensitive DoD data at rest.'
  impact 0.5
  ref 'DPMS Target PDA/PED'
  tag check_id: 'C-11537r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14202'
  tag rid: 'SV-14813r2_rule'
  tag stig_id: 'WIR0190'
  tag gtitle: 'FIPS validated encryption for data at rest'
  tag fix_id: 'F-34090r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECWN-1'
end
