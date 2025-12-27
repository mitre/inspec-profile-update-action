control 'SV-99233' do
  title 'The SLES for vRealize must use mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

SLES for vRealize  utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.'
  desc 'check', 'Check the "/etc/default/passwd" file:

# grep CRYPT /etc/default/passwd

If the "CRYPT" setting in the "/etc/default/passwd" file is not present, or not set to "SHA256" or "SHA512", this is a finding.

If the "CRYPT_FILES" setting in the "/etc/default/passwd" file is not present, or not set to "SHA256" or "SHA512", this is a finding.'
  desc 'fix', 'Edit the "/etc/default/passwd" file and add or change the "CRYPT" variable setting so that it contains:

CRYPT=sha256 
OR
CRYPT=sha512 

Edit the "/etc/default/passwd" file and add or change the "CRYPT_FILES" variable setting so that it contains:

CRYPT_FILES=sha256 
OR
CRYPT_FILES=sha512'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88275r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88583'
  tag rid: 'SV-99233r1_rule'
  tag stig_id: 'VROM-SL-000710'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-95325r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
