control 'SV-230210' do
  title 'IBM RACF exit ICHPWX11 for password phrases must be installed and properly configured.'
  desc 'Use of a complex password phrase helps to increase the time and resources required to compromise the password. Password phrase complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password phrase complexity is one factor of several that determines how long it takes to crack a password. The more complex the password phrase, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', "From a system console screen issue the following modify command:
F AXR,IRRPHREX LIST

Review the results of the modify command. 

If all of the following options are listed, this is not a finding.

-The number of required character types is 4
(assures that at least 1 upper case, 1 lower case, 1 number, and 1 special character is used in Password phrase)

-The user's name is not contained in the password phrase
(Only 3 consecutive characters of the user's name are allowed)

-The minimum password phrase length checked is 15

-The user ID is not contained in the password phrase
(Only 3 consecutive characters of the user ID are allowed)

-The new password phrase is at least 50% changed positions of the old password phrase.
(These positions need to be consecutive to cause a failure and this check is not case sensitive)

-A minimum list of 8 restricted words are being checked:
'IBM' , 'RACF', 'PASSWORD', 'PHRASE', 'PASSPHRASE', 'SECRET', 'IBMUSER', 'SYS1'

If the modify command fails or returns the following message in the system log, this is a finding.

IRX0406E REXX exec load file REXXLIB does not contain exec member IRRPHREX."
  desc 'fix', %q(Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

For z/OS release 1.12 through z/OS release 2.1, APARs OA43998 and OA43999 must be applied.

Install exit IRRPHREX according to the following guidelines:
REXX Parameter Setting

Phr_minlen = 15 /* Minimum length */
Phr_maxlen = 100 /* Maximum passphrase length */
numbers = '0123456789' 
letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' 
special = '&*@ :=!-%.#?|-' " 
Phr_allowed_chars = numbers||letters||special 
Phr_leading_blanks = 'no' 
Phr_trailing_blanks = 'no' 
Phr_name_allowed = 'no' 
Phr_name_minlen = 3 
Phr_repeat_chars_chk = 'yes' 
Phr_userid_allowed = 'no' 
Phr_req_types = 4 
Phr_min_unique = Phr_minlen % 2 /* 'Half' of chars must be unique  */  
Phr_min_unique_norm = 'yes' 
Phr_word_unique = 0 
Phr_word_unique_upper = 'yes' 
Phr_word_minlen = 4 
Phr_dict.1 = 'IBM' 
Phr_dict.2 = 'RACF' 
Phr_dict.3 = 'PASSWORD'
Phr_dict.4 = 'PHRASE' 
Phr_dict.5 = 'PASSPHRAS
Phr_dict.6 = 'SECRET' 
Phr_dict.7 = 'IBMUSER' 
Phr_dict.8 = 'SYS1'

Note: RACF exit ICHPHX11 is coded to call a System REXX named IRRPHREX, so the name cannot be changed without a corresponding change to ICHPWX11.

System REXX requires that this exec (IRRPHREX) reside in the REXXLIB concatenation.

Update parameters in IRRPHREX according to table Parameters for RACF IRRPWREX as listed above.)
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-32543r868821_chk'
  tag severity: 'medium'
  tag gid: 'V-230210'
  tag rid: 'SV-230210r918623_rule'
  tag stig_id: 'RACF-ES-000785'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-32519r868822_fix'
  tag 'documentable'
  tag legacy: ['V-56691', 'SV-70951']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
