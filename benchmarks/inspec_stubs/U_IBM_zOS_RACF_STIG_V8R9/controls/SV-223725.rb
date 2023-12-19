control 'SV-223725' do
  title 'IBM RACF exit ICHPWX01 must be installed and properly configured.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

'
  desc 'check', "From a system console screen issue the following modify command:
F AXR,IRRPWREX LIST

Review the results of the modify command. 

If the following options are listed, this is not a finding.

-The number of required character types is 4
(assures that at least 1 upper case, 1 lower case, 1 number, and 1 special character is used in Password)

-The user's name cannot be contained in the password
(Only 3 consecutive characters of the user's name are allowed)

-The minimum word length checked is 8

-The user ID cannot be contained in the password
(Only 3 consecutive characters of the user ID are allowed)

-Only 3 unchanged positions of the current password are allowed
(These positions need to be consecutive to cause a failure and this check is not case sensitive)

-No more than 0 pairs of repeating characters are allowed
(This check is not case sensitive)

-A minimum list of 33 restricted prefix strings is being checked:
APPL APR AUG ASDF BASIC CADAM DEC DEMO FEB FOCUS GAME IBM JAN JUL
JUN LOG MAR MAY NET NEW NOV OCT PASS ROS SEP SIGN SYS TEST TSO
VALID VTAM XXX 1234

If the modify command fails or returns the following message in the system log, this is a finding.

IRX0406E REXX exec load file REXXLIB does not contain exec member IRRPWREX."
  desc 'fix', "Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

For z/OS release 1.12 through z/OS release 2.1 APARs OA43998 and OA43999 must be applied.

Install exit IRRPWREX according to the following guidelines:
REXX Parameter Setting
STIG_Compliant 'yes' 
Pwd_minlen 8
numbers '0123456789'
Lower_letters 'abcdefghijklmnopqrstuvwxyz'
Upper_letters 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
special '$@#.<+|&!*-%_>?:'
Pwd_allowed_chars numbers||Upper_letters||special
Pwd_req_types 4
Pwd_name_allowed 'no'
Pwd_name_minlen 8
Pwd_name_chars 4
Pwd_min_unique 3
Pwd_min_unique_upper 'yes'
Pwd_max_unchanged 3
Pwd_max_unchanged_upper 'yes'
Pwd_max_unchanged_consecutive 'yes'
Pwd_all_unique 'no'
Pwd_no_consecutive 'no'
Pwd_no_consecutive_upper 'yes'
Pwd_min_new 4
Pwd_userID_allowed 'no'
Pwd_userID_chars 4
Pwd_repeat_chars 0
Pwd_repeat_upper 'yes'
Pwd_dict.0 8 /* Change this as words are added and deleted */
Pwd_dict.1 'IBM'
Pwd_dict.2 'RACF'
Pwd_dict.3 'PASSWORD'
Pwd_dict.4 'PHRASE'
Pwd_dict.5 'SECRET'
Pwd_dict.6 'IBMUSER'
Pwd_dict.7 'SYS1'
Pwd_dict.8 '12345678'
Pwd_dict.9 '99999999'
Pwd_prefix.0 33 /* Change this as values are added and deleted
Pwd_prefix.1 'APPL'
Pwd_prefix.2 'APR'
Pwd_prefix.3 'AUG'
Pwd_prefix.4 'ASDF'
Pwd_prefix.5 'BASIC'
Pwd_prefix.6 'CADAM'
Pwd_prefix.7 'DEC'
Pwd_prefix.8 'DEMO'
Pwd_prefix.9 'FEB'
Pwd_prefix.10 'FOCUS'
Pwd_prefix.11 'GAME'
Pwd_prefix.12 'IBM'
Pwd_prefix.13 'JAN'
Pwd_prefix.14 'JUL'
Pwd_prefix.15 'JUN'
Pwd_prefix.16 'LOG'
Pwd_prefix.17 'MAR'
Pwd_prefix.18 'MAY'
Pwd_prefix.19 'NET'
Pwd_prefix.20 'NEW'
Pwd_prefix.21 'NOV'
Pwd_prefix.22 'OCT'
Pwd_prefix.23 'PASS'
Pwd_prefix.24 'ROS'
Pwd_prefix.25 'SEP'
Pwd_prefix.26 'SIGN'
Pwd_prefix.27 'SYS'
Pwd_prefix.28 'TEST'
Pwd_prefix.29 'TSO'
Pwd_prefix.30 'VALID'
Pwd_prefix.31 'VTAM'
Pwd_prefix.32 'XXX'
Pwd_prefix.33 '1234'

Note: RACF exit ICHPWX01 is coded to call a System REXX named IRRPWREX, so the name cannot be changed without a corresponding change to ICHPWX01.

System REXX requires that this exec (IRRPWREX) reside in the REXXLIB concatenation.

Update parameters in IRRPWREX according to table Parameters for RACF IRRPWREX as listed above."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25398r514863_chk'
  tag severity: 'medium'
  tag gid: 'V-223725'
  tag rid: 'SV-223725r868820_rule'
  tag stig_id: 'RACF-ES-000780'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-25386r868819_fix'
  tag satisfies: ['SRG-OS-000070-GPOS-00038', 'SRG-OS-000071-GPOS-00039', 'SRG-OS-000072-GPOS-00040', 'SRG-OS-000266-GPOS-00101', 'SRG-OS-000480-GPOS-00225']
  tag 'documentable'
  tag legacy: ['SV-107261', 'V-98157']
  tag cci: ['CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000366', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'CM-6 b', 'IA-5 (1) (a)']
end
