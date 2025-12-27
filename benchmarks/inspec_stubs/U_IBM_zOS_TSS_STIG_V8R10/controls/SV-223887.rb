control 'SV-223887' do
  title 'IBM z/OS must use NIST FIPS-validated cryptography to protect passwords in the security database.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

'
  desc 'check', 'From the ISPF command shell line enter:
TSS MODIFY(STATUS)

If either of the following is included, this is not a finding.

AES_ENCRYPTION(Active,128)
AES_ENCRYPTION(Active,256)'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option.

Develop a plan of action to implement the control option as specified below:

Convert passwords/password phrases from Triple-DES encryption to 128-bit AES or 256-bit encryption by running TSSMAINT (with the AESENCRYPT option specified) and then running TSSXTEND to copy the old security file to the new security file.

Please consult CA-TSS Installation guide for more information.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25560r516060_chk'
  tag severity: 'high'
  tag gid: 'V-223887'
  tag rid: 'SV-223887r877728_rule'
  tag stig_id: 'TSS0-ES-000140'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-25548r516061_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000074-GPOS-00042']
  tag 'documentable'
  tag legacy: ['V-98481', 'SV-107585']
  tag cci: ['CCI-000196', 'CCI-000197']
  tag nist: ['IA-5 (1) (c)', 'IA-5 (1) (c)']
end
